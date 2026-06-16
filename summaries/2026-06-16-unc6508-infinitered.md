# Technical Analysis Report: UNC6508 INFINITERED Campaign (2026-06-16)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-16
Version: 1.1 (FINAL)

## Executive Summary

UNC6508 is a People's Republic of China (PRC)-nexus espionage group identified by Google's Threat Intelligence Group (GTIG) that conducted a sustained intrusion campaign against North American medical, academic, and military research organizations from September 2023 through November 2025 -- remaining undetected for over 14 months. The group exploited externally facing REDCap (Research Electronic Data Capture) servers for initial access, then deployed a custom three-component backdoor called INFINITERED to harvest credentials, maintain persistence through software upgrades, and execute arbitrary commands via HTTP cookie-based C2. After achieving domain administrator access through credential replay, UNC6508 abused a built-in Google Workspace content compliance feature to silently BCC emails matching approximately 150 espionage-aligned keywords to an attacker-controlled Gmail account (BebitaBarefoot774@gmail[.]com). The intelligence collection priorities -- AI, unmanned systems, cyber offensive programs, medical research, and military strategy -- align directly with PRC strategic interests.

This report provides the complete technical breakdown of INFINITERED's architecture, all published IOCs, MITRE ATT&CK mapping, and production-ready detection rules (Sigma, YARA, Snort/Suricata).

## Background: REDCap and Google Workspace in Research Environments

**REDCap** (Research Electronic Data Capture) is a web-based application used by over 6,800 institutions worldwide for clinical and translational research data management. It is the de facto standard for electronic data capture in academic medical research. REDCap is self-hosted (typically on-premises or in cloud environments like AWS Elastic Beanstalk), runs on PHP/MySQL, and stores highly sensitive protected health information (PHI), research protocols, and clinical trial data. Critically, REDCap allows legacy software versions to run alongside current builds, creating a "downgrade attack" surface where unpatched versions remain accessible.

**Google Workspace** is widely adopted by academic and research institutions for email and collaboration. Its administrative console includes "content compliance rules" -- a legitimate DLP feature that scans inbound and outbound email against keyword patterns and can route matching messages to specified recipients. This feature operates at the mail-transport layer with no user-visible indicators, making it an ideal silent exfiltration vector when abused by an attacker with administrative access.

## Attack Timeline (All Times UTC)

| Timeframe | Event |
|-----------|-------|
| September 2023 | Earliest known compromise of externally facing REDCap server; initial reconnaissance and web shell (help.php) deployment |
| ~December 2023 | INFINITERED malware deployed (~3 months post-initial compromise); credential harvester, backdoor, and upgrade interceptor components installed |
| December 2023 -- September 2024 | Credential harvesting phase; REDCap login credentials captured, encrypted, and stored in redcap_sessions table with prefix `xc32038474a` |
| ~September 2024 | Lateral movement achieved; harvested credentials replayed to obtain domain administrator account access (>12 months after initial compromise) |
| ~September 2024 | Google Workspace content compliance rule "Patroit" created; silent BCC exfiltration to BebitaBarefoot774@gmail[.]com begins |
| July 2025 | Collection keywords updated to include "chikungunya" -- correlating with Guangdong province outbreak in China |
| November 2025 | Threat actor detected and disrupted; Google disables exfiltration Gmail account |
| February 2026 | Google GTIG first surfaces UNC6508 and REDCap backdoor publicly |
| June 15, 2026 | GTIG publishes detailed technical report with full IOC set and YARA rules |

## Root Cause: Exploitation of Unpatched REDCap Servers

The initial access vector was exploitation of externally facing REDCap servers running older, vulnerable versions. Although the specific CVE exploited has not been definitively identified, REDCap had multiple patches for critical remote-code execution vulnerabilities throughout 2023, including:

- A **PHP deserialization RCE** vulnerability in REDCap 13.0.1+ that could be exploited via manipulated HTTP requests to CDIS-related pages
- A **blind SQL injection** vulnerability on data entry forms and survey pages allowing arbitrary SQL command execution

The presence of legacy REDCap versions running alongside current builds provided UNC6508 with a wider attack surface. REDCap's architecture -- a PHP/MySQL application with database credentials stored in configuration files -- meant that compromising the web tier immediately yielded database access and, through credential reuse, broader network access.

## Technical Analysis of the Malicious Payload

### INFINITERED Architecture Overview

INFINITERED is a custom, modular PHP backdoor consisting of three distinct components that trojanize legitimate REDCap system files:

1. **Dropper and Upgrade Interceptor** -- maintains persistence across REDCap version updates
2. **Credential Harvester** -- captures login credentials from the REDCap authentication flow
3. **HTTP Cookie-Based Backdoor** -- provides remote access and command execution

### Component 1: Dropper and Upgrade Interceptor

The upgrade interceptor is INFINITERED's most sophisticated component. It hooks into REDCap's upgrade process to ensure malicious code persists across software updates.

**Mechanism:**
1. When a REDCap upgrade ZIP is processed, the dropper reads the current infected `Upgrade.php`
2. It extracts malicious code delimited by the GUID `b49e334d-9c01-463e-9bc5-00a6920fb66e` (base64: `YjQ5ZTMzNGQtOWMwMS00NjNlLTliYzUtMDBhNjkyMGZiNjZl`)
3. The extracted code is injected into three files within the upgrade package:
   - **Custom hooks configuration file** (backdoor component)
   - **Authentication system file** (credential harvester)
   - **Upgrade system file** (self-replication)
4. For AWS Elastic Beanstalk deployments, additional persistence steps are performed

**Key Code Pattern:**
```php
$dummy_marker = base64_decode('YjQ5ZTMzNGQtOWMwMS00NjNlLTliYzUtMDBhNjkyMGZiNjZl');
$pattern = "/$dummy_marker(.*?)$dummy_marker/s";
// Extracts malicious code between GUID markers and reinjects into upgrade package
```

This ensures that every future REDCap upgrade automatically reinjects the backdoor -- the malware "survives" patching.

### Component 2: Credential Harvester

The credential harvester silently captures usernames and passwords from REDCap login POST requests.

**Storage Mechanism:**
- Credentials are encrypted using REDCap's own encryption routine
- Stored in the legitimate `redcap_sessions` database table
- Session IDs are prefixed with `xc32038474a` followed by a 20-character hex-encoded timestamp
- Records are set to expire after 60 days

**Key Code Pattern:**
```php
$str = encrypt($currentUTC . '[::]' . $_POST['username'] . '[::]' . $_POST['password']);
$session_id = 'xc32038474a' . substr(bin2hex($currentUTC), -20);
// INSERT INTO redcap_sessions (session_id, session_data, session_expiration) VALUES (...)
```

### Component 3: HTTP Cookie-Based Backdoor

The backdoor is injected into the REDCap custom hooks system file and executes on every page load.

**C2 Communication:** Commands are delivered via the `REDCAP-TOKEN` HTTP cookie. The cookie value contains a magic flag prefix followed by encrypted command data.

**Command Set:**

| Command Tag | Function |
|-------------|----------|
| `00` | Execute arbitrary system commands via `shell_exec` |
| `02` | Upload file to server (destination path + content) |
| `03` | Retrieve stolen credentials from database |
| `04` | Delete stolen credential records |
| `05` | Execute arbitrary SQL queries |
| `ej671a16i7fd8202nu6ltfg5p6x7u` | Download arbitrary file from server |
| Empty payload (beacon) | Return OS info, PHP version, working directory, database credentials |

### Google Workspace Content Compliance Rule Abuse

After obtaining domain administrator access through credential replay (~12 months post-initial compromise), UNC6508 created a content compliance rule in Google Workspace:

- **Rule Name:** "Patroit" (misspelled "Patriot" -- suggests manual creation)
- **Action:** Silent BCC to `BebitaBarefoot774@gmail[.]com`
- **Matching Criteria:** ~150 keywords, email addresses, and patterns
- **Intelligence Priorities:**
  - Geo-strategic policy
  - Military strategy and equipment
  - Advanced technology (AI, uncrewed/unmanned vehicles)
  - Offensive cyber programs
  - Medical research (notably "chikungunya" -- added July 2025 during Guangdong outbreak)
  - Professional contact information

This technique left **no malware on the mail server, no separate exfiltration tool, and no unusual network traffic** -- the emails were forwarded using Google's own infrastructure, making detection exceptionally difficult.

### Operational Security (OpSec)

UNC6508 demonstrated sophisticated operational security:

- **OBF Networks:** All infrastructure connections routed through US-based IP addresses via compromised routers (including ASUS residential routers), VPS nodes, and other compromised IoT devices
- **IP Address 23[.]169[.]65[.]49:** Identified as a compromised ASUS router used as an OBF relay for admin logins
- **Gmail Account Acquisition:** BebitaBarefoot774@gmail[.]com was obtained through a mass creation service and used exclusively for data exfiltration
- **Living-off-the-Land:** Abuse of legitimate cloud features (Google Workspace compliance rules) and legitimate application behavior (REDCap session management) minimized anomalous indicators

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs use defanged notation: `[.]` replaces dots in domains/IPs, `[@]` replaces @ in emails.

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| Email | BebitaBarefoot774[@]gmail[.]com | Exfiltration inbox (disabled by Google) |
| IP Address | 23[.]169[.]65[.]49 | Compromised ASUS router used as OBF relay for admin logins |

### File Indicators (SHA256)

| SHA256 Hash | Component |
|-------------|-----------|
| `ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7` | Persistence module (help.php web shell) |
| `db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136` | Credential Harvester |
| `c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b` | Credential Harvester (variant) |
| `8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec` | Backdoor |
| `51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045` | Dropper |
| `4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b` | Dropper (variant) |
| `58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86` | Dropper (variant) |

### Host Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `b49e334d-9c01-463e-9bc5-00a6920fb66e` | GUID | INFINITERED code delimiter in upgrade interceptor |
| `YjQ5ZTMzNGQtOWMwMS00NjNlLTliYzUtMDBhNjkyMGZiNjZl` | Base64 | Base64-encoded GUID delimiter |
| `xc32038474a` | String | Credential harvester session ID prefix in redcap_sessions table |
| `ej671a16i7fd8202nu6ltfg5p6x7u` | String | INFINITERED backdoor magic flag / file download command tag |
| `REDCAP-TOKEN` | Cookie Name | HTTP cookie parameter used for C2 communication |
| `help.php` | Filename | Initial web shell deployed on REDCap server |
| `Patroit` | Rule Name | Google Workspace content compliance rule (misspelled) |

## MITRE ATT&CK Mapping

| Tactic | ID | Technique | UNC6508 Context |
|--------|----|-----------|-----------------|
| Initial Access | T1190 | Exploit Public-Facing Application | Exploitation of vulnerable REDCap servers |
| Persistence | T1505.003 | Server Software Component: Web Shell | help.php web shell and INFINITERED backdoor deployment |
| Persistence | T1554 | Compromise Host Software Binary | REDCap upgrade process hijacking for cross-version persistence |
| Defense Evasion | T1027 | Obfuscated Files or Information | Base64 encoding of malicious payloads in PHP files |
| Defense Evasion | T1090.003 | Proxy: Multi-hop Proxy | OBF network routing through compromised ASUS routers and VPS |
| Defense Evasion | T1689 | Downgrade Attack | Exploitation of legacy REDCap versions running alongside current |
| Credential Access | T1056.003 | Input Capture: Web Portal Capture | Credential harvester capturing POST login data |
| Credential Access | T1555 | Credentials from Password Stores | Extraction of database credentials from REDCap configuration files |
| Lateral Movement | T1078 | Valid Accounts | Credential replay from harvested REDCap logins to domain admin |
| Collection | T1114.003 | Email Collection: Email Forwarding Rule | "Patroit" content compliance rule for email BCC exfiltration |
| Collection | T1213 | Data from Information Repositories | Keyword-based email collection targeting ~150 intelligence terms |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP cookie-based C2 via REDCAP-TOKEN parameter |
| Exfiltration | T1567 | Exfiltration Over Web Service | Silent Gmail forwarding via Google Workspace infrastructure |

## Impact Assessment

**Scope:** Multiple North American organizations compromised across clinical providers, academic medical centers, US military health institutions, professional advocacy groups, and health regulatory bodies.

**Data at Risk:**
- Protected health information (PHI) and clinical research data from REDCap databases
- Email communications matching espionage-aligned keywords across defense, AI, medical research, and cyber operations
- REDCap login credentials for all users at compromised institutions
- Database credentials and service account credentials
- Domain administrator credentials (via credential reuse)

**Strategic Intelligence Value:** The collection priorities -- AI research, unmanned vehicle systems, offensive cyber programs, military strategy, and medical research (including disease-specific terms like "chikungunya") -- directly align with PRC strategic interests and suggest state-directed tasking.

**Assessment of Scale:** GTIG researcher Patrick Whitsell noted: "We have some evidence to suggest this is a large threat group with multiple sub-teams, but this is not confirmed." The broader targeting scope suggested by keyword patterns indicates the identified medical research victims may represent only a subset of UNC6508's total target set.

## Detection & Remediation

### Immediate Detection Actions

1. **Audit Google Workspace content compliance rules:** Search for rules created by non-standard administrators, rules with external BCC destinations, and specifically the rule name "Patroit"
2. **Query REDCap database for credential theft artifacts:**
   ```sql
   SELECT * FROM redcap_sessions WHERE session_id LIKE 'xc32038474a%';
   ```
3. **Scan REDCap file system with YARA:** Deploy the `G_Backdoor_INFINITERED_1` rule (provided below) against all PHP files in REDCap installations
4. **Review web server logs for REDCAP-TOKEN cookies:** Search access logs for requests containing the `REDCAP-TOKEN` cookie parameter outside of legitimate API contexts
5. **Check for help.php web shell:** Verify whether `help.php` exists in unexpected REDCap directories and review its content
6. **Hash check:** Compare all PHP files in REDCap installations against the 7 known SHA256 IOCs listed above
7. **Network monitoring:** Alert on connections to `23[.]169[.]65[.]49`

### Remediation

1. **Patch REDCap immediately:** Update to the latest version and remove ALL legacy versions running alongside current builds
2. **Rotate all credentials:** REDCap database credentials, service accounts, domain administrator passwords, and all user accounts that logged into compromised REDCap instances
3. **Review Google Workspace admin audit logs:** Examine `CREATE_GMAIL_SETTING` and `CHANGE_GMAIL_SETTING` events for unauthorized rule creation timestamps
4. **Implement phishing-resistant MFA:** Enforce hardware security keys for all administrator accounts (Google Workspace and REDCap)
5. **Segment REDCap infrastructure:** Ensure REDCap servers cannot be used as a pivot to domain administrator access; enforce unique credentials across security domains
6. **Monitor for reinfection:** The upgrade interceptor means that upgrading REDCap while the backdoor is present will reinfect the new version -- a clean installation from known-good media is required

## Detection Rules

### YARA Rule: INFINITERED Backdoor (GTIG Official)

> **Source:** Google Threat Intelligence Group
> **Compile status:** COMPILED (yarac -- clean)
> **Confidence:** HIGH -- official vendor rule covering all three INFINITERED components with both plaintext and base64 string variants

```yara
rule G_Backdoor_INFINITERED_1 {
    meta:
        author = "Google Threat Intelligence Group (GTIG)"
        description = "Detects INFINITERED custom backdoor deployed by UNC6508 against REDCap servers"
        date = "2026-06-15"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research"
        threat_actor = "UNC6508"
        tlp = "WHITE"
    strings:
        $magic_flag = "ej671a16i7fd8202nu6ltfg5p6x7u"
        $magic_flag_base64 = "ej671a16i7fd8202nu6ltfg5p6x7u" base64
        $marker = "b49e334d-9c01-463e-9bc5-00a6920fb66e"
        $marker_base64 = "YjQ5ZTMzNGQtOWMwMS00NjNlLTliYzUtMDBhNjkyMGZiNjZl"
        $s1 = "substr($cookieValue, strlen($magic_flag));"
        $s2 = "getcwd(), php_uname(), phpversion(), $_SERVER['SERVER_SOFTWARE']"
        $s3 = "'data' => encrypt($data, $key)"
        $s4 = "$data = shell_exec($command);"
        $s5 = "move_uploaded_file($tmpPath, $fileName)"
        $s6 = "$data = implode('|', $fields)"
        $b_s1 = "substr($cookieValue, strlen($magic_flag));" base64
        $b_s2 = "getcwd(), php_uname(), phpversion(), $_SERVER['SERVER_SOFTWARE']" base64
        $b_s3 = "'data' => encrypt($data, $key)" base64
        $b_s4 = "$data = shell_exec($command);" base64
        $b_s5 = "move_uploaded_file($tmpPath, $fileName)" base64
        $b_s6 = "$data = implode('|', $fields)" base64
        $t1 = "(isset($_POST['username']) && $_POST['password'])"
        $t2 = "INSERT INTO redcap_sessions (session_id, session_data, session_expiration) VALUES ('$session_id', '$str', FROM_UNIXTIME($expiration_timestamp))"
        $t3 = "encrypt($currentUTC . '[::]' . $_POST['username'] . '[::]' . $_POST['password']);"
        $t4 = "redcap_connect.php"
        $b_t1 = "(isset($_POST['username']) && $_POST['password'])" base64
        $b_t2 = "INSERT INTO redcap_sessions (session_id, session_data, session_expiration) VALUES ('$session_id', '$str', FROM_UNIXTIME($expiration_timestamp))" base64
        $b_t3 = "encrypt($currentUTC . '[::]' . $_POST['username'] . '[::]' . $_POST['password']);" base64
        $b_t4 = "redcap_connect.php" base64
        $u1 = "$zip->open($filename) === TRUE)"
        $u2 = "$hooks_encode ="
        $u3 = "$auth_encode ="
        $u4 = "$file_content_hooks = $zip->getFromName($file_hooks);"
        $u5 = "$file_content_auth = $zip->getFromName($file_auth);"
        $u6 = "$file_content_upgrade = $zip->getFromName($file_upgrade);"
        $u7 = "str_replace($search_content, $hooks_decode, $file_content_hooks);"
        $u8 = "str_replace($search_content, $upgrade_decode, $file_content_upgrade);"
        $u9 = "str_replace($search_content, $auth_decode, $file_content_auth);"
        $b_u1 = "$zip->open($filename) === TRUE)" base64
        $b_u2 = "$hooks_encode =" base64
        $b_u3 = "$auth_encode =" base64
        $b_u4 = "$file_content_hooks = $zip->getFromName($file_hooks);" base64
        $b_u5 = "$file_content_auth = $zip->getFromName($file_auth);" base64
        $b_u6 = "$file_content_upgrade = $zip->getFromName($file_upgrade);" base64
        $b_u7 = "str_replace($search_content, $hooks_decode, $file_content_hooks);" base64
        $b_u8 = "str_replace($search_content, $upgrade_decode, $file_content_upgrade);" base64
        $b_u9 = "str_replace($search_content, $auth_decode, $file_content_auth);" base64
        $filemarker = "<?php"
    condition:
        filesize < 1MB and $filemarker in (0 .. 128) and (((any of ($magic*) or any of ($marker*)) and (any of ($s*) or any of ($t*) or any of ($u*))) or 4 of ($s*) or 4 of ($b_s*) or all of ($t*) or all of ($b_t*) or 6 of ($u*) or 6 of ($b_u*))
}
```

### YARA Rule: INFINITERED Credential Harvester (Actioner)

> **Compile status:** COMPILED (yarac -- clean)
> **Confidence:** HIGH -- targets unique attacker-chosen session ID prefix and credential storage patterns

```yara
rule UNC6508_INFINITERED_CredHarvester {
    meta:
        author = "Actioner"
        description = "Detects INFINITERED credential harvester component targeting REDCap sessions table"
        date = "2026-06-16"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research"
        threat_actor = "UNC6508"
        tlp = "WHITE"
    strings:
        $session_prefix = "xc32038474a"
        $session_prefix_base64 = "xc32038474a" base64
        $delim = "[::]"
        $redcap_sessions = "redcap_sessions"
        $encrypt_cred = "encrypt($currentUTC"
        $post_user = "$_POST['username']"
        $post_pass = "$_POST['password']"
        $php = "<?php"
    condition:
        filesize < 500KB and $php in (0 .. 128) and ($session_prefix or $session_prefix_base64) and 2 of ($delim, $redcap_sessions, $encrypt_cred, $post_user, $post_pass)
}
```

### YARA Rule: INFINITERED Web Shell (Actioner)

> **Compile status:** COMPILED (yarac -- clean)
> **Confidence:** HIGH -- matches on unique GUID + C2 cookie or shell execution patterns

```yara
rule UNC6508_INFINITERED_WebShell_HelpPHP {
    meta:
        author = "Actioner"
        description = "Detects INFINITERED help.php web shell used for initial persistence on REDCap"
        date = "2026-06-16"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research"
        threat_actor = "UNC6508"
        tlp = "WHITE"
    strings:
        $guid = "b49e334d-9c01-463e-9bc5-00a6920fb66e"
        $guid_b64 = "YjQ5ZTMzNGQtOWMwMS00NjNlLTliYzUtMDBhNjkyMGZiNjZl"
        $cookie_c2 = "REDCAP-TOKEN"
        $magic = "ej671a16i7fd8202nu6ltfg5p6x7u"
        $shell_exec = "shell_exec($command)"
        $php = "<?php"
    condition:
        filesize < 1MB and $php in (0 .. 128) and (any of ($guid, $guid_b64, $magic)) and ($cookie_c2 or $shell_exec)
}
```

### Sigma Rule: Google Workspace Content Compliance Rule Creation

> **Compile status:** COMPILED (sigma check -- 0 errors, 0 issues; converts to Splunk and LogScale)
> **Confidence:** MEDIUM -- detects any compliance rule creation/modification (broad), not specific to "Patroit"; useful as a baseline hunt query

```yaml
title: UNC6508 Google Workspace Content Compliance Rule Abuse - Patroit
id: a3f7b2c1-9e04-4d8a-b5f6-7c2d1e3a8b09
status: experimental
description: |
    Detects creation or modification of Google Workspace content compliance rules
    that may be used for email exfiltration, as observed in UNC6508 campaign.
    The threat actor created a rule named "Patroit" (misspelled) that silently
    BCC'd emails matching ~150 keywords to an attacker-controlled Gmail account.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research
author: Actioner
date: 2026-06-16
tags:
    - attack.collection
    - attack.t1114.003
    - attack.exfiltration
    - attack.t1567
logsource:
    product: google_workspace
    service: admin
detection:
    selection_event:
        eventName:
            - 'CREATE_GMAIL_SETTING'
            - 'CHANGE_GMAIL_SETTING'
    selection_setting:
        settingName|contains:
            - 'ContentCompliance'
            - 'ComplianceRule'
    condition: selection_event and selection_setting
falsepositives:
    - Legitimate administrator creating content compliance rules for DLP or regulatory purposes
    - Routine compliance rule updates
level: medium
```

**Splunk conversion:**
```
eventName IN ("CREATE_GMAIL_SETTING", "CHANGE_GMAIL_SETTING") settingName IN ("*ContentCompliance*", "*ComplianceRule*")
```

### Sigma Rule: Suspicious BCC Forwarding to External Gmail

> **Compile status:** COMPILED (sigma check -- 0 errors, 0 issues; converts to Splunk and LogScale)
> **Confidence:** MEDIUM -- detects compliance rule + BCC + external Gmail pattern; may trigger on legitimate compliance routing to Gmail accounts

```yaml
title: UNC6508 Suspicious BCC Email Forwarding to External Gmail Account
id: d8e5a1c3-6b09-4f2e-a7d4-9c3b5e1f8a02
status: experimental
description: |
    Detects Google Workspace email routing rules that BCC messages to external
    Gmail accounts. UNC6508 abused content compliance rules to silently BCC
    matching emails to BebitaBarefoot774@gmail.com for data exfiltration.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research
author: Actioner
date: 2026-06-16
tags:
    - attack.collection
    - attack.t1114.003
    - attack.exfiltration
    - attack.t1567
logsource:
    product: google_workspace
    service: admin
detection:
    selection_event:
        eventName:
            - 'CREATE_GMAIL_SETTING'
            - 'CHANGE_GMAIL_SETTING'
    selection_bcc:
        newValue|contains:
            - 'bcc'
    selection_external:
        newValue|contains:
            - '@gmail.com'
            - '@googlemail.com'
    condition: selection_event and selection_bcc and selection_external
falsepositives:
    - Legitimate business forwarding rules to external Gmail accounts
    - Compliance archiving configurations
level: medium
```

**Splunk conversion:**
```
eventName IN ("CREATE_GMAIL_SETTING", "CHANGE_GMAIL_SETTING") newValue IN ("*bcc*") newValue IN ("*@gmail.com*", "*@googlemail.com*")
```

### Sigma Rule: Known UNC6508 C2 Infrastructure

> **Compile status:** COMPILED (sigma check -- 0 errors, 0 issues; converts to Splunk and LogScale)
> **Confidence:** HIGH (IOC-specific) -- but IP may be reassigned over time; time-bound applicability

```yaml
title: UNC6508 Known C2 Infrastructure Connection
id: f2a9c4b7-3e08-4d1a-b6c5-8a1d7e3f9b04
status: experimental
description: |
    Detects network connections to known UNC6508 infrastructure IP address
    23.169.65.49, identified as a compromised ASUS router used as an
    operational relay (OBF) node for administrative logins.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research
author: Actioner
date: 2026-06-16
tags:
    - attack.command-and-control
    - attack.t1090.003
    - attack.t1071.001
logsource:
    category: firewall
detection:
    selection:
        dst_ip:
            - '23.169.65.49'
    condition: selection
falsepositives:
    - IP may be reassigned to legitimate services over time - verify current ownership
level: high
```

**Splunk conversion:**
```
dst_ip="23.169.65.49"
```

### Sigma Rule: REDCAP-TOKEN Cookie C2

> **Compile status:** COMPILED (sigma check -- 0 errors, 0 issues; converts to Splunk and LogScale)
> **Confidence:** MEDIUM -- REDCAP-TOKEN may appear in legitimate API contexts; filter provided

```yaml
title: UNC6508 INFINITERED REDCap Cookie-Based C2 Communication
id: c7b3e8a1-4d06-4f9a-a2c5-6e8d1b3f7a09
status: experimental
description: |
    Detects HTTP requests to REDCap servers containing the REDCAP-TOKEN
    cookie parameter used by INFINITERED backdoor for command and control.
    The backdoor executes commands delivered via this cookie on every
    REDCap page load.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research
author: Actioner
date: 2026-06-16
tags:
    - attack.command-and-control
    - attack.t1071.001
    - attack.execution
    - attack.t1059.004
logsource:
    category: webserver
detection:
    selection:
        cs-cookie|contains: 'REDCAP-TOKEN'
    filter_legitimate:
        cs-uri-stem|contains:
            - '/api/'
            - '/API/'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate REDCap API token usage in cookies - review URI context
    - REDCap mobile app authentication
level: medium
```

**Splunk conversion:**
```
"cs-cookie"="*REDCAP-TOKEN*" NOT ("cs-uri-stem" IN ("*/api/*", "*/API/*"))
```

### Sigma Rule: INFINITERED Credential Storage Artifact

> **Compile status:** COMPILED (sigma check -- 0 errors, 0 issues; converts to Splunk and LogScale)
> **Confidence:** HIGH -- xc32038474a is a unique attacker-chosen prefix with near-zero false positive rate

```yaml
title: UNC6508 INFINITERED Credential Storage Session ID Prefix
id: e1d4f6a8-5c03-4b7e-9a2d-3f7c8b1e6a05
status: experimental
description: |
    Detects database queries or log entries containing the INFINITERED
    credential harvester session ID prefix "xc32038474a" used to store
    stolen REDCap credentials in the redcap_sessions table.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research
author: Actioner
date: 2026-06-16
tags:
    - attack.credential-access
    - attack.t1056.003
    - attack.persistence
    - attack.t1505.003
logsource:
    category: application
    product: mysql
detection:
    selection:
        query|contains: 'xc32038474a'
    condition: selection
falsepositives:
    - Extremely unlikely in production databases - this is a unique attacker-chosen prefix
level: critical
```

**Splunk conversion:**
```
query="*xc32038474a*"
```

### Sigma Rule: INFINITERED Web Shell Access

> **Compile status:** COMPILED (sigma check -- 0 errors, 0 issues; converts to Splunk and LogScale)
> **Confidence:** MEDIUM -- help.php POST in REDCap context is suspicious but not definitive; requires investigation

```yaml
title: UNC6508 INFINITERED Web Shell Access - help.php
id: b5a2c9d7-8e01-4f3a-a6b4-2d7c1e5f9a03
status: experimental
description: |
    Detects HTTP access to help.php web shell deployed by UNC6508 on
    REDCap servers for initial persistence and file upload capability.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research
author: Actioner
date: 2026-06-16
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.initial-access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_uri:
        cs-uri-stem|endswith: '/help.php'
    selection_method:
        cs-method:
            - 'POST'
    selection_context:
        cs-uri-stem|contains: 'redcap'
    condition: selection_uri and selection_method and selection_context
falsepositives:
    - Legitimate REDCap help page POST requests (uncommon)
    - Other web applications with help.php endpoints
level: medium
```

**Splunk conversion:**
```
"cs-uri-stem"="*/help.php" "cs-method"="POST" "cs-uri-stem"="*redcap*"
```

### Sigma Rule: INFINITERED Known Malicious File Hashes

> **Compile status:** COMPILED (sigma check -- 0 errors, 0 issues; converts to Splunk and LogScale)
> **Confidence:** HIGH -- exact SHA256 hash matches for known malware samples

```yaml
title: UNC6508 INFINITERED Known Malicious File Hashes
id: a8c3d5e7-1b04-4f6a-9c2e-5d8a3f7b1e06
status: experimental
description: |
    Detects files matching known SHA256 hashes of INFINITERED malware
    components including the persistence module (help.php), credential
    harvesters, backdoor, and droppers deployed by UNC6508.
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research
author: Actioner
date: 2026-06-16
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.credential-access
    - attack.t1056.003
logsource:
    category: file_event
detection:
    selection:
        Hashes|contains:
            - 'ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7'
            - 'db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136'
            - 'c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b'
            - '8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec'
            - '51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045'
            - '4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b'
            - '58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86'
    condition: selection
falsepositives:
    - None expected - these are known malicious file hashes
level: critical
```

**Splunk conversion:**
```
Hashes IN ("*ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7*", "*db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136*", "*c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b*", "*8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec*", "*51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045*", "*4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b*", "*58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86*")
```

### Snort/Suricata Rules: INFINITERED Network Detection

> **Compile status:** UNCOMPILED (structural check only)
> **Confidence:** HIGH -- targets unique INFINITERED strings in HTTP traffic

```
# Detect REDCAP-TOKEN cookie containing INFINITERED magic flag
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"UNC6508 INFINITERED C2 Magic Flag in Cookie"; flow:to_server,established; content:"Cookie|3a|"; http_header; content:"REDCAP-TOKEN"; http_header; content:"ej671a16i7fd8202nu6ltfg5p6x7u"; http_header; reference:url,cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research; classtype:trojan-activity; sid:2026061601; rev:1;)

# Detect INFINITERED GUID marker in HTTP response (backdoor beacon)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"UNC6508 INFINITERED Beacon GUID in Response"; flow:to_client,established; content:"b49e334d-9c01-463e-9bc5-00a6920fb66e"; reference:url,cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research; classtype:trojan-activity; sid:2026061602; rev:1;)

# Detect INFINITERED GUID marker base64-encoded in traffic
alert http any any -> any any (msg:"UNC6508 INFINITERED Base64 GUID Marker"; flow:established; content:"YjQ5ZTMzNGQtOWMwMS00NjNlLTliYzUtMDBhNjkyMGZiNjZl"; reference:url,cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research; classtype:trojan-activity; sid:2026061603; rev:1;)

# Detect outbound connection to known UNC6508 OBF node
alert ip $HOME_NET any -> 23.169.65.49 any (msg:"UNC6508 Known OBF Infrastructure Connection"; reference:url,cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research; classtype:trojan-activity; sid:2026061604; rev:1;)
```

## Lessons Learned

1. **Legitimate cloud features are the new exfiltration channel.** UNC6508's abuse of Google Workspace content compliance rules produced zero malware artifacts, zero unusual network traffic, and zero user-visible indicators. Organizations must audit administrative cloud configurations -- not just endpoints -- as part of threat hunting.

2. **Credential reuse across security domains enables catastrophic lateral movement.** UNC6508 pivoted from REDCap application credentials to domain administrator access because users shared passwords across domains. Enforcing unique credentials and phishing-resistant MFA across all tiers is essential.

3. **Legacy application versions are a hidden attack surface.** REDCap's architecture of allowing old versions to run alongside current builds gave UNC6508 a "downgrade attack" vector. Organizations should audit for and remove all legacy application instances from production environments.

4. **Upgrade mechanisms can be weaponized for persistence.** INFINITERED's upgrade interceptor ensured that patching the application reinfected the new version. Traditional "patch and forget" remediation is insufficient when the upgrade process itself is compromised -- clean installation from verified media is the only safe recovery path.

5. **Patient adversaries exploit the detection gap.** UNC6508 waited ~3 months before deploying malware, then ~12 months before lateral movement. This slow operational tempo evades time-based anomaly detection and correlation rules. Long-retention logging and periodic retrospective threat hunts are critical for detecting low-and-slow campaigns.

6. **Research infrastructure is a high-value espionage target.** The targeting of REDCap -- a platform used by 6,800+ institutions for clinical research -- demonstrates that threat actors increasingly target domain-specific research applications rather than generic enterprise systems.

## Sources

- [Google Cloud Blog - Public and Private Medical Community Targeted by China-Nexus Threat Actor](https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research) -- **Primary source.** GTIG's full technical report with IOCs, YARA rules, code samples, and MITRE ATT&CK mapping.
- [CyberScoop - Google exposes China espionage group that's been lurking in networks undetected since 2023](https://cyberscoop.com/google-unc6508-china-espionage-threat/)
- [The Hacker News - Chinese Hackers Abused Google Workspace Rules to Steal Research and Defense Emails](https://thehackernews.com/2026/06/chinese-hackers-abused-google-workspace.html)
- [Security Affairs - China-linked actor UNC6508 spent two years inside medical research networks](https://securityaffairs.com/193667/apt/china-linked-actor-unc6508-spent-two-years-inside-medical-research-networks.html)
- [BleepingComputer - Chinese hackers breach REDCap servers, steal medical research](https://www.bleepingcomputer.com/news/security/chinese-hackers-breach-redcap-servers-steal-medical-research/)
- [Help Net Security - Chinese hackers breached North American research institutions via REDCap servers](https://www.helpnetsecurity.com/2026/06/15/chinese-hackers-redcap-medical-research-institutions-breach/)
- [The Register - Google says PRC-linked spies hid in medical research networks for more than a year](https://www.theregister.com/research/2026/06/15/google-says-prc-linked-spies-hid-in-medical-research-networks-for-more-than-a-year/5254547)
- [SC Media - China-linked group uses InfiniteRed malware to target medical research institutions](https://www.scworld.com/brief/china-linked-group-uses-infinitered-malware-to-target-medical-research-institutions)
- [The Next Web - A built-in Google Workspace feature became a Chinese espionage group's favourite exfiltration tool](https://thenextweb.com/news/chinese-hackers-unc6508-google-workspace-redcap-medical-military-research)
- [University of Nebraska Medical Center - Notice of REDCap data security incident](https://www.unmc.edu/newsroom/2026/04/17/notice-of-redcap-data-security-incident/) -- Potentially related REDCap breach with overlapping timeline (Sep 2023 -- Feb 2026)
