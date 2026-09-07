# Technical Analysis Report: PaperCut NG/MF Zero-Day Exploitation Chain (CVE-2026-81578 & CVE-2026-82078)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-02
Version: 1.0

## Executive Summary

Two zero-day vulnerabilities in PaperCut NG and MF print management software -- CVE-2026-81578 (CVSS 8.8, authentication bypass) and CVE-2026-82078 (CVSS 9.4, unsafe dynamic class loading) -- are being chained by threat actors to achieve unauthenticated remote code execution with SYSTEM privileges on internet-facing PaperCut Application Servers. PaperCut disclosed the flaws on August 27, 2026, after confirming active exploitation in customer environments. CISA added both CVEs to its Known Exploited Vulnerabilities catalog on August 31, 2026, with a federal remediation deadline of September 14, 2026.

Approximately 47% of tracked PaperCut installations remain on version 23 or earlier, for which no patch exists. Huntress confirmed exploitation in at least two customer environments across education, healthcare, and construction sectors, with roughly 204 internet-facing instances remaining vulnerable as of August 31. Post-exploitation activity includes system reconnaissance (whoami, ver, tasklist), deployment of SimpleHelp and AnyDesk remote access tools, and anti-forensic deletion of server logs and malicious payloads. The exploit chain requires no credentials and is described as "point and shoot" by researchers. A Metasploit module is publicly available.

## Background: PaperCut NG/MF

PaperCut NG (for small/mid organizations) and PaperCut MF (for enterprise) are widely deployed print management and cost-control solutions used by over 100 million users across 89,000+ organizations worldwide. The software runs an Application Server with a web management interface (typically on port 9191/9192) built on the Apache Tapestry web framework, backed by an embedded Apache Derby database. The Application Server runs as a Windows service (pc-app.exe / SimpleService.exe) with SYSTEM privileges, or as a daemon on Linux. Internet-facing deployments of the web management interface are the primary attack surface.

PaperCut experienced a similar exploitation event in 2023 (CVE-2023-27350, CVSS 9.8), which was exploited by Russian state actors and the Lace Tempest threat group. The current vulnerability chain follows a structurally similar pattern -- authentication bypass chained with code execution -- but exploits different underlying mechanisms.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-08-26 | Earliest confirmed exploitation activity observed by Huntress in education-sector customer environment |
| 2026-08-27 | PaperCut publishes urgent security advisory disclosing active exploitation of undisclosed vulnerability |
| 2026-08-28 02:10 AEST | PaperCut releases Emergency Patch Release 1 for versions 25 and 26; CVE-2026-81578 and CVE-2026-82078 assigned |
| 2026-08-28 (later) | Emergency patches extended to version 24; initial patch bypass discovered by attackers |
| 2026-08-29-30 | Huntress, Rapid7, and Horizon3 publish technical analyses; PaperCut adds IOCs to advisory |
| 2026-08-31 | Emergency Patch Release 2 with additional hardening; CISA adds both CVEs to KEV catalog |
| 2026-09-01 | Third emergency patch addressing SAML login flow bypass |
| 2026-09-14 | CISA BOD 22-01 remediation deadline for federal agencies |

## Root Cause: Apache Tapestry Direct Request Authentication Bypass (CVE-2026-81578)

The initial access vector exploits a flaw in PaperCut's use of the Apache Tapestry web framework. Tapestry's "complex direct" request format allows a single HTTP request to specify one page for rendering/display and a separate page whose component or action is actually executed. PaperCut's authorization logic validates access permissions only against the displayed page, not the page owning the executed component.

By crafting requests that reference a public, unauthenticated page (Error, Exception, or Home) for display while targeting administrative components (ConfigEditor, UserList) for execution, an attacker bypasses all authentication checks. The vulnerable URI pattern is:

```
/app?service=direct/1/Error/ConfigEditor/quickFindForm
/app?service=direct/1/Error/ConfigEditor/$Form
/app?service=direct/1/Error/UserList/$QuickFind.$Form
```

The path segment value ("1") is arbitrary, and "Error" can be substituted with "Exception" or "Home" -- any public page bypasses the auth check.

## Technical Analysis of the Malicious Payload

### 1. Authentication Bypass via Tapestry Direct Requests (CVE-2026-81578)

The attacker sends crafted HTTP GET/POST requests to the PaperCut web interface targeting the ConfigEditor administrative component through public page references. This grants unauthenticated access to modify server configuration parameters, specifically the external user-lookup database settings:

- `user-lookup.db-driver` -- database driver class name
- `user-lookup.db-url` -- JDBC connection URL
- `user-lookup.id-to-username-sql` -- SQL query for user lookups
- `user-lookup.enabled` -- enables the external lookup feature

### 2. JDBC-Based Code Execution via Unsafe Class Loading (CVE-2026-82078)

With configuration access obtained, the attacker reconfigures the database connection parameters to exploit PaperCut's unsafe dynamic class loading. The application instantiates database driver classes based on configurable driver names without validating them against an approved allowlist. The exploitation chain proceeds:

1. **Configure Derby in-memory database**: Set `user-lookup.db-url` to `jdbc:derby:memory:pwn;create=true` to initialize an attacker-controlled in-memory Derby database
2. **Activate foreignViews feature**: Use a Derby CALL statement to enable the foreignViews subsystem
3. **Open H2 JDBC URL**: Redirect to an attacker-controlled H2 JDBC connection string containing an inline INIT statement
4. **JavaScript trigger execution**: The H2 INIT statement creates a JavaScript-backed database trigger. PaperCut bundles the Nashorn JavaScript engine, which the trigger leverages to execute arbitrary OS commands
5. **Command execution**: The Nashorn engine calls `java.lang.Runtime.getRuntime().exec()` to spawn system commands with SYSTEM privileges (the security context of the PaperCut server process)

### 3. Post-Exploitation Activity

Recovered malicious Java .class payloads (with randomized 5-character filenames such as `Udydn.class` and `Moo97.class`) executed the following sequence:

1. **System reconnaissance**: Base64-encoded commands decoded and executed:
   - `d2hvYW1pICYgdmVy` decodes to `whoami & ver`
   - `d2hvYW1pICYgdmVyICYgdGFza2xpc3Q=` decodes to `whoami & ver & tasklist`
2. **Output capture**: Results written to files like `Udydn.out` in `<install>/server/data/content/`
3. **Remote access tool deployment**: 
   - SimpleHelp installed as Windows service "Remote Access Service" (SimpleService.exe) at `C:\ProgramData\JWrapper-Remote Access\`
   - AnyDesk installed as secondary redundant access channel
   - Payloads downloaded from external file-sharing service (sendit.sh)
4. **Domain enumeration**: Listing domain controllers, enumerating logged-on users and sessions
5. **Anti-forensics**: Deletion of server.log, malicious .class files, .cmd files, and .out output files

### 4. Platform-Specific Behavior

#### Windows
- PaperCut runs as `pc-app.exe` under SYSTEM context
- Exploitation spawns `cmd.exe` as child of `pc-app.exe`
- .class payloads deployed to `C:\Program Files\PaperCut MF\server\lib\`
- Output written to `C:\Program Files\PaperCut MF\server\data\content\`
- SimpleHelp persistence via `C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\restricted\`
- `charmap.exe` observed spawned with SYSTEM privileges as exploitation indicator

#### Linux
- PaperCut runs as `pc-app` daemon process
- Exploitation spawns `/bin/sh` or `/bin/bash` as child
- .class payloads deployed to `<install>/server/lib/`
- Same JDBC exploitation chain applies (platform-agnostic Java payload)

### 5. Anti-Forensics / Evasion Techniques

- **Log deletion**: server.log files deleted or truncated to remove exploitation evidence (T1070.004)
- **Payload self-deletion**: Malicious .class, .cmd, and .out files deleted after execution
- **Randomized filenames**: 5-character randomized names for deployed artifacts to evade static IOC matching
- **OS-agnostic payloads**: Java .class files work across Windows and Linux deployments
- **First patch bypass**: Attackers found a way around Emergency Patch Release 1 within ~24 hours, necessitating a second emergency patch

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### File System

| Platform | Path | Description |
|----------|------|-------------|
| Windows | `C:\Program Files\PaperCut MF\server\lib\<5-char>.class` | Malicious Java class payload (e.g., Udydn.class, Moo97.class) |
| Windows | `C:\Program Files\PaperCut MF\server\data\content\<5-char>.cmd` | Command execution script |
| Windows | `C:\Program Files\PaperCut MF\server\data\content\<5-char>.out` | Reconnaissance output file |
| Windows | `C:\ProgramData\JWrapper-Remote Access\` | SimpleHelp installation directory |
| Windows | `C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\restricted\` | SimpleHelp persistence config |
| Linux | `<install>/server/lib/<5-char>.class` | Malicious Java class payload |
| Linux | `<install>/server/data/content/<5-char>.cmd` | Command execution script |
| Linux | `<install>/server/data/content/<5-char>.out` | Reconnaissance output file |
| Both | `<install>/server/data/internal/derby.log` | Derby database log (exploitation evidence) |

### Log-Based Indicators (server.log)

| Log Entry | Significance |
|-----------|-------------|
| `DB URL: jdbc:derby:memory:pwn;create=true` | Derby in-memory database creation for exploitation |
| `ERROR No suitable driver found for jdbc:no:x` | Failed driver load during exploit chain setup |
| `ERROR DatabaseUtils - Database error looking up cardID: VALUES CAST` | SQL injection via JDBC exploitation |
| `DB URL: jdbc:no:x DB Driver: <5-char random name>` | Malicious driver class loading attempt |
| `memory:C:\Program Files\PaperCut MF\server\data\internal\pwn` | Derby exploitation path reference |
| `cafebabe` (in hex context within log) | Java class magic bytes in database error output |

### Process-Based Indicators

| Parent Process | Child Process | Context |
|----------------|---------------|---------|
| `pc-app.exe` | `cmd.exe` | Post-exploitation command execution |
| `pc-app.exe` | `charmap.exe` | SYSTEM-privilege exploitation indicator |
| `cmd.exe` (under pc-app.exe) | `whoami.exe` | Reconnaissance |
| `cmd.exe` (under pc-app.exe) | `tasklist.exe` | Process enumeration |
| `cmd.exe` (under pc-app.exe) | `nltest.exe` | Domain controller enumeration |
| `cmd.exe` (under pc-app.exe) | `net.exe` / `net1.exe` | User and session enumeration |

### Service-Based Indicators

| Service Name | Binary | Description |
|-------------|--------|-------------|
| Remote Access Service | SimpleService.exe | SimpleHelp RAT persistence |
| AnyDesk Service | AnyDesk.exe | AnyDesk RAT persistence |

### Behavioral

- Missing, unexpectedly truncated, or deleted PaperCut `server.log` files
- Unexpected `.class` files appearing in `server/lib/` directory with short (5-character) random names
- PaperCut Application Server process spawning command shells or reconnaissance tools
- Network connections from PaperCut server to external file-sharing services (sendit[.]sh)
- Unexpected Windows services named "Remote Access Service" on PaperCut servers
- Base64-encoded command strings in process command lines: `d2hvYW1pICYgdmVy`, `d2hvYW1pICYgdmVyICYgdGFza2xpc3Q=`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Exploitation of internet-facing PaperCut web management interface via chained CVE-2026-81578 + CVE-2026-82078 |
| T1059.003 | Windows Command Shell | pc-app.exe spawning cmd.exe to execute reconnaissance commands (whoami, ver, tasklist) |
| T1059.004 | Unix Shell | Equivalent exploitation on Linux spawning /bin/sh or /bin/bash |
| T1059.007 | JavaScript | Nashorn JavaScript engine used via H2 database trigger for arbitrary command execution |
| T1219 | Remote Access Software | Deployment of SimpleHelp and AnyDesk remote access tools for persistent access |
| T1082 | System Information Discovery | Execution of "ver" command to identify OS version |
| T1033 | System Owner/User Discovery | Execution of "whoami" to identify current user context |
| T1057 | Process Discovery | Execution of "tasklist" to enumerate running processes |
| T1018 | Remote System Discovery | Domain controller enumeration via nltest |
| T1070.004 | File Deletion | Deletion/truncation of PaperCut server.log and derby.log application log files; self-deletion of malicious .class, .cmd, and .out payloads |
| T1105 | Ingress Tool Transfer | Download of SimpleHelp and AnyDesk installers from external file-sharing (sendit.sh) |
| T1543.003 | Windows Service | SimpleHelp installed as "Remote Access Service" Windows service |

## Impact Assessment

- **Breadth**: PaperCut claims 100M+ users across 89,000+ organizations. Approximately 47% of tracked installations run v23 or earlier with no available patch. Shadowserver identified ~204 internet-facing vulnerable instances as of August 31, with concentrations in the US (~60), Denmark, and Ireland.
- **Depth**: Full SYSTEM-level RCE on the Application Server. Compromise enables domain enumeration, lateral movement, and persistent remote access. The exploit chain requires zero credentials and is trivially reproducible (Metasploit module available).
- **Stealth**: Attackers delete logs and self-destruct payloads. The initial exploitation activity observed by Huntress completed in under 2 minutes. First emergency patch was bypassed within ~24 hours.
- **Targeted sectors**: Education (primary), healthcare, construction.

## Detection & Remediation

### Immediate Detection

Administrators should immediately check for compromise indicators:

```bash
# Check for suspicious .class files in PaperCut server lib directory
# Windows:
dir "C:\Program Files\PaperCut MF\server\lib\*.class" /O-D
dir "C:\Program Files\PaperCut NG\server\lib\*.class" /O-D

# Linux:
find /opt/papercut/server/lib/ -name "*.class" -newer /opt/papercut/server/lib/papercut-server.jar

# Check for exploitation artifacts in data/content
# Windows:
dir "C:\Program Files\PaperCut MF\server\data\content\*.cmd"
dir "C:\Program Files\PaperCut MF\server\data\content\*.out"

# Linux:
find /opt/papercut/server/data/content/ -name "*.cmd" -o -name "*.out"

# Search server.log for JDBC exploitation strings
# Windows:
findstr /i "jdbc:derby:memory:pwn" "C:\Program Files\PaperCut MF\server\logs\server.log"
findstr /i "jdbc:no:x" "C:\Program Files\PaperCut MF\server\logs\server.log"
findstr /i "VALUES CAST" "C:\Program Files\PaperCut MF\server\logs\server.log"

# Linux:
grep -i "jdbc:derby:memory:pwn\|jdbc:no:x\|VALUES CAST" /opt/papercut/server/logs/server.log

# Check for unexpected services (Windows)
sc query "Remote Access Service"
wmic service where "name like '%AnyDesk%'" get name,pathname,startmode

# Check if server.log was recently deleted or is suspiciously small
# Windows:
dir "C:\Program Files\PaperCut MF\server\logs\server.log"
# Linux:
ls -la /opt/papercut/server/logs/server.log
stat /opt/papercut/server/logs/server.log
```

### Remediation

1. **Immediate**: Remove PaperCut web management interface from public internet exposure using firewall rules, network ACLs, or VPN requirements -- regardless of whether exploitation indicators are observed
2. **Patch**: Apply Emergency Patch Release 2 (or later) for PaperCut NG/MF versions 24, 25, and 26. Versions 23 and earlier have no patch -- upgrade to a supported version. Note that this upgrade is non-trivial: approximately 47% of tracked installations remain on v23 or earlier, and organizations on these versions may face license, compatibility, or budget barriers to a full major-version upgrade. Until the upgrade is completed, network-level mitigations (firewall rules, VPN-only access) are the only available protection
3. **If compromised**: Isolate the server, secure backups, wipe and rebuild from clean backups. Do not attempt to clean a compromised server in place
4. **Verify**: Confirm Site Servers and secondary/print servers are also updated
5. **Hunt**: Search for SimpleHelp and AnyDesk installations, check for "Remote Access Service" Windows service, review process creation logs for pc-app.exe child processes

### Long-Term Hardening

- Never expose PaperCut web management interfaces directly to the internet
- Restrict Application Server access to trusted IP addresses via allowlist
- Implement network segmentation between print management infrastructure and critical assets
- Deploy endpoint detection on PaperCut servers with monitoring for process creation anomalies
- Enable web server access logging on PaperCut instances for forensic readiness
- Monitor for PaperCut security advisories and apply patches within vendor-recommended windows

## Detection Rules

20 detection rules (6 Sigma, 6 Suricata, 6 Snort, 2 YARA) target the specific exploitation chain and post-exploitation activity documented by Huntress, Rapid7, and Horizon3 for CVE-2026-81578 / CVE-2026-82078. All rules use indicators drawn directly from confirmed incidents; the primary caveat is that attackers may vary their post-exploitation tooling while the initial access vector (Tapestry direct requests) remains structurally consistent.

### Sigma Rule 1: PaperCut Tapestry Direct Request Authentication Bypass Attempt

Detects the HTTP-level exploitation of CVE-2026-81578 via Tapestry direct service requests targeting administrative components through public pages.

**Compile**: sigma check pass, sigma convert splunk pass, sigma convert log_scale pass | **Confidence**: high

```yaml
title: PaperCut NG/MF Tapestry Direct Request Authentication Bypass Attempt
id: 8a3e1c7b-4f2d-4e9a-b6c1-2d5f8a0e3b7c
status: experimental
description: >
    Detects HTTP requests to PaperCut NG/MF web interface using Apache Tapestry
    direct request format to bypass authentication and invoke administrative
    components (ConfigEditor, UserList). This is the initial step in the
    CVE-2026-81578 / CVE-2026-82078 exploitation chain enabling pre-auth RCE.
references:
    - https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/
    - https://www.huntress.com/blog/papercut-actively-exploited
    - https://horizon3.ai/attack-research/vulnerabilities/cve-2026-81578-cve-2026-82078/
author: Actioner
date: 2026-09-02
tags:
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_uri:
        cs-uri-query|contains: 'service=direct'
    selection_component:
        cs-uri-query|contains:
            - 'ConfigEditor'
            - 'UserList'
    selection_page:
        cs-uri-query|contains:
            - '/Error/'
            - '/Exception/'
            - '/Home/'
    condition: selection_uri and selection_component and selection_page
falsepositives:
    - Legitimate PaperCut administrative access using Tapestry direct service calls (unlikely with Error/Exception page references)
level: critical
```

<!-- Audit: sigma check 0 errors 0 issues (attacktag validator excluded due to proxy blocking MITRE ATT&CK data fetch); sigma convert --without-pipeline -t splunk produces valid SPL; sigma convert --without-pipeline -t log_scale produces valid LogScale query. Detection values use real (non-defanged) strings matching raw web server log format. Field cs-uri-query is standard webserver logsource field per W3C Extended Log Format. -->

### Sigma Rule 2: PaperCut pc-app.exe Spawning Suspicious Child Process

Detects the post-exploitation process chain where pc-app.exe spawns command shells or reconnaissance tools, the primary behavioral indicator confirmed by PaperCut and Huntress.

**Compile**: sigma check pass, sigma convert splunk pass, sigma convert log_scale pass | **Confidence**: high

```yaml
title: PaperCut pc-app.exe Spawning Suspicious Child Process
id: 9b4f2d8c-5a3e-4f1b-c7d2-3e6a9b1f4c8d
status: experimental
description: >
    Detects the PaperCut application process (pc-app.exe) spawning command shell
    or reconnaissance processes, consistent with post-exploitation behavior
    observed in CVE-2026-81578 / CVE-2026-82078 exploitation campaigns.
references:
    - https://www.huntress.com/blog/papercut-actively-exploited
    - https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/
author: Actioner
date: 2026-09-02
tags:
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\pc-app.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\whoami.exe'
            - '\tasklist.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\nltest.exe'
            - '\charmap.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate PaperCut scripting integrations that invoke command shells (rare, should be baselined)
level: critical
```

<!-- Audit: sigma check 0 errors 0 issues. Field names Image, ParentImage match Sysmon EID 1 and Windows 4688 schema. Process list limited to tools confirmed in exploitation observations: cmd.exe, whoami.exe, tasklist.exe, net.exe, net1.exe, nltest.exe (Huntress), and charmap.exe (CISA/SecurityAffairs). powershell.exe and pwsh.exe removed -- not documented in any confirmed incident at specific altitude. -->

### Sigma Rule 3: PaperCut JDBC Exploitation Artifacts in Application Logs

Detects the distinctive JDBC error strings that appear in PaperCut server.log during CVE-2026-82078 exploitation.

**Portability caveat**: `product: papercut` is not in the standard Sigma taxonomy. Deployers need a custom log ingestion pipeline that maps PaperCut `server.log` entries into the `Message` field. The `--without-pipeline` conversion produces raw field names that will not match default Splunk indexes (or other SIEM field mappings) without manual adjustment.

**Compile**: sigma check pass, sigma convert splunk pass, sigma convert log_scale pass | **Confidence**: high

```yaml
title: PaperCut JDBC Exploitation Artifacts in Application Logs
id: 7c5a3e9d-6b4f-4d2c-a8e1-4f7b0c2d5a9e
status: experimental
description: >
    Detects log entries in PaperCut server.log indicating JDBC-based exploitation
    of CVE-2026-82078. Attackers reconfigure the database driver to load malicious
    Java classes via Derby or H2 JDBC connections.
references:
    - https://www.huntress.com/blog/papercut-actively-exploited
    - https://horizon3.ai/attack-research/vulnerabilities/cve-2026-81578-cve-2026-82078/
author: Actioner
date: 2026-09-02
tags:
    - attack.t1190
logsource:
    category: application
    product: papercut
detection:
    selection:
        - Message|contains: 'jdbc:derby:memory:pwn'
        - Message|contains: 'No suitable driver found for jdbc:no:x'
        - Message|contains: 'Database error looking up cardID: VALUES CAST'
        - Message|contains|all:
            - 'DB URL:'
            - 'jdbc:no:x'
    condition: selection
falsepositives:
    - Misconfigured PaperCut database connections referencing Derby in-memory databases (extremely unlikely with 'pwn' keyword)
level: critical
```

<!-- Audit: sigma check 0 errors 0 issues. Uses application logsource with product:papercut -- requires custom log ingestion pipeline mapping PaperCut server.log to the Message field. All four detection strings are verbatim from PaperCut official advisory and Huntress analysis. "pwn" in JDBC URL is highly distinctive. -->

### Sigma Rule 4: Suspicious Java Class File in PaperCut Server Library Directory

Detects file creation events for .class files in PaperCut installation directories, the mechanism by which CVE-2026-82078 deploys malicious code.

**Compile**: sigma check pass, sigma convert splunk pass, sigma convert log_scale pass | **Confidence**: medium

```yaml
title: Suspicious Java Class File in PaperCut Server Library Directory
id: 6d7b4c2e-8a5f-4e3d-b9c1-5a8e0d3f6b7a
status: experimental
description: >
    Detects creation of Java .class files in the PaperCut server lib directory,
    consistent with exploitation of CVE-2026-82078. Attackers deploy short-named
    (typically 5-character) malicious .class files for arbitrary code execution.
references:
    - https://www.huntress.com/blog/papercut-actively-exploited
    - https://horizon3.ai/attack-research/vulnerabilities/cve-2026-81578-cve-2026-82078/
author: Actioner
date: 2026-09-02
tags:
    - attack.t1105
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\PaperCut'
        TargetFilename|endswith: '.class'
    filter_known:
        TargetFilename|contains:
            - '\server\lib-ext\'
            - '\WEB-INF\classes\'
    condition: selection and not filter_known
falsepositives:
    - Legitimate PaperCut plugin or extension installation deploying .class files (should be validated against change management)
level: high
```

<!-- Audit: sigma check 0 errors 0 issues. Medium confidence due to potential FPs from legitimate PaperCut updates or plugin installations deploying .class files. Filter excludes known extension directories. Requires Sysmon EID 11 (FileCreate) or equivalent file monitoring. -->

### Sigma Rule 5: Remote Access Tool Installation Following PaperCut Exploitation

Detects SimpleHelp or AnyDesk deployment from the PaperCut process context, matching the specific post-exploitation tooling observed by Huntress.

**Compile**: sigma check pass, sigma convert splunk pass, sigma convert log_scale pass | **Confidence**: medium

```yaml
title: Remote Access Tool Installation Following PaperCut Exploitation
id: 5e8c3d1f-9b6a-4f4e-c0d2-6b9f1e4a7c8b
status: experimental
description: >
    Detects installation of SimpleHelp or AnyDesk remote access tools via
    PaperCut process context, consistent with post-exploitation activity
    observed in CVE-2026-81578 / CVE-2026-82078 campaigns.
references:
    - https://www.helpnetsecurity.com/2026/08/31/papercut-attack-remote-access-tools/
    - https://www.huntress.com/blog/papercut-actively-exploited
author: Actioner
date: 2026-09-02
tags:
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\pc-app.exe'
    selection_rat:
        - Image|endswith:
            - '\SimpleService.exe'
            - '\AnyDesk.exe'
        - CommandLine|contains:
            - 'SimpleHelp'
            - 'AnyDesk'
            - 'JWrapper-Remote Access'
        - OriginalFileName:
            - 'SimpleService.exe'
            - 'AnyDesk.exe'
    condition: selection_parent and selection_rat
falsepositives:
    - Authorized remote access tool deployment through PaperCut (should be correlated with change tickets)
level: high
```

<!-- Audit: sigma check 0 errors 0 issues. Medium confidence because future campaigns may use different RAT tooling; these specific tools (SimpleHelp, AnyDesk) are tied to the observed August 2026 campaign. Parent constrained to pc-app.exe only -- cmd.exe removed to avoid firing on any cmd.exe spawning RAT binaries system-wide, which is too broad for specific altitude. -->

### Sigma Rule 6: PaperCut Server Log File Deletion

Detects deletion of PaperCut server.log or derby.log, the anti-forensics behavior observed in all confirmed exploitation incidents.

**Compile**: sigma check pass, sigma convert splunk pass, sigma convert log_scale pass | **Confidence**: high

```yaml
title: PaperCut Server Log File Deletion or Truncation
id: 4f9d2e0a-7c8b-4a5f-d1e3-7c0a2f5b8d9e
status: experimental
description: >
    Detects deletion or modification of PaperCut server.log files, which is
    anti-forensics behavior observed during CVE-2026-81578 / CVE-2026-82078
    exploitation. Attackers delete logs to cover exploitation artifacts.
references:
    - https://www.huntress.com/blog/papercut-actively-exploited
    - https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/
author: Actioner
date: 2026-09-02
tags:
    - attack.t1070.004
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|contains: '\PaperCut'
        TargetFilename|endswith:
            - '\server.log'
            - '\derby.log'
    condition: selection
falsepositives:
    - PaperCut log rotation processes (typically rename, not delete)
level: high
```

<!-- Audit: sigma check 0 errors 0 issues. MITRE tag corrected to T1070.004 (File Deletion) -- these are application log files on Windows, not Linux/Mac system logs (T1070.002). Requires Sysmon EID 23/26 (FileDelete) or equivalent. Log rotation typically renames files rather than deleting, so delete events on these specific files are high-signal. -->

### Suricata Rules: PaperCut Tapestry Auth Bypass Network Detection

Six Suricata rules detecting the HTTP-level exploitation requests targeting ConfigEditor and UserList components through Error, Exception, and Home public pages -- covering all documented bypass variants.

**Compile**: suricata -T pass ("Configuration provided was successfully loaded") | **Confidence**: high

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut NG/MF Tapestry Auth Bypass Exploit Attempt (CVE-2026-81578)"; flow:established,to_server; http.uri; content:"service=direct"; content:"ConfigEditor"; content:"/Error/"; classtype:web-application-attack; reference:cve,2026-81578; reference:url,horizon3.ai/attack-research/vulnerabilities/cve-2026-81578-cve-2026-82078/; metadata:author Actioner, created_at 2026-09-02, cve CVE-2026-81578; sid:2100100; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut NG/MF Tapestry Auth Bypass via Exception Page (CVE-2026-81578)"; flow:established,to_server; http.uri; content:"service=direct"; content:"ConfigEditor"; content:"/Exception/"; classtype:web-application-attack; reference:cve,2026-81578; reference:url,horizon3.ai/attack-research/vulnerabilities/cve-2026-81578-cve-2026-82078/; metadata:author Actioner, created_at 2026-09-02, cve CVE-2026-81578; sid:2100101; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut NG/MF UserList QuickFind Auth Bypass (CVE-2026-81578)"; flow:established,to_server; http.uri; content:"service=direct"; content:"UserList"; content:"/Error/"; classtype:web-application-attack; reference:cve,2026-81578; reference:url,rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/; metadata:author Actioner, created_at 2026-09-02, cve CVE-2026-81578; sid:2100102; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut NG/MF Tapestry Auth Bypass via Home Page - ConfigEditor (CVE-2026-81578)"; flow:established,to_server; http.uri; content:"service=direct"; content:"ConfigEditor"; content:"/Home/"; classtype:web-application-attack; reference:cve,2026-81578; reference:url,horizon3.ai/attack-research/vulnerabilities/cve-2026-81578-cve-2026-82078/; metadata:author Actioner, created_at 2026-09-02, cve CVE-2026-81578; sid:2100103; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut NG/MF UserList Auth Bypass via Exception Page (CVE-2026-81578)"; flow:established,to_server; http.uri; content:"service=direct"; content:"UserList"; content:"/Exception/"; classtype:web-application-attack; reference:cve,2026-81578; reference:url,rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/; metadata:author Actioner, created_at 2026-09-02, cve CVE-2026-81578; sid:2100104; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut NG/MF UserList Auth Bypass via Home Page (CVE-2026-81578)"; flow:established,to_server; http.uri; content:"service=direct"; content:"UserList"; content:"/Home/"; classtype:web-application-attack; reference:cve,2026-81578; reference:url,rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/; metadata:author Actioner, created_at 2026-09-02, cve CVE-2026-81578; sid:2100105; rev:1;)
```

<!-- Audit: suricata -T -S suricata_papercut_exploit.rules -l /tmp/actioner exit 0. Uses http.uri dot-notation sticky buffer (Suricata 7.x). Three content matches per rule provide sufficient specificity; all three strings must appear in the URI to trigger. Direction $EXTERNAL_NET -> $HOME_NET assumes PaperCut server is inside protected network. Six rules cover all combinations: ConfigEditor x {Error, Exception, Home} and UserList x {Error, Exception, Home}. -->

### Snort Rules: PaperCut Tapestry Auth Bypass Network Detection

Six equivalent Snort 3 rules for the same HTTP exploitation patterns, covering all ConfigEditor and UserList bypass variants through Error, Exception, and Home public pages.

**Compile**: not available (snort not installed) | **Confidence**: high

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut NG/MF Tapestry Auth Bypass Exploit Attempt (CVE-2026-81578)"; flow:established, to_server; http_uri; content:"service=direct", fast_pattern; content:"ConfigEditor"; content:"/Error/"; classtype:web-application-attack; reference:cve,2026-81578; reference:url,horizon3.ai/attack-research/vulnerabilities/cve-2026-81578-cve-2026-82078/; metadata:author Actioner, created 2026-09-02; sid:2100200; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut NG/MF Tapestry Auth Bypass via Exception Page (CVE-2026-81578)"; flow:established, to_server; http_uri; content:"service=direct", fast_pattern; content:"ConfigEditor"; content:"/Exception/"; classtype:web-application-attack; reference:cve,2026-81578; reference:url,horizon3.ai/attack-research/vulnerabilities/cve-2026-81578-cve-2026-82078/; metadata:author Actioner, created 2026-09-02; sid:2100201; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut NG/MF UserList QuickFind Auth Bypass (CVE-2026-81578)"; flow:established, to_server; http_uri; content:"service=direct", fast_pattern; content:"UserList"; content:"/Error/"; classtype:web-application-attack; reference:cve,2026-81578; reference:url,rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/; metadata:author Actioner, created 2026-09-02; sid:2100202; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut NG/MF Tapestry Auth Bypass via Home Page - ConfigEditor (CVE-2026-81578)"; flow:established, to_server; http_uri; content:"service=direct", fast_pattern; content:"ConfigEditor"; content:"/Home/"; classtype:web-application-attack; reference:cve,2026-81578; reference:url,horizon3.ai/attack-research/vulnerabilities/cve-2026-81578-cve-2026-82078/; metadata:author Actioner, created 2026-09-02; sid:2100203; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut NG/MF UserList Auth Bypass via Exception Page (CVE-2026-81578)"; flow:established, to_server; http_uri; content:"service=direct", fast_pattern; content:"UserList"; content:"/Exception/"; classtype:web-application-attack; reference:cve,2026-81578; reference:url,rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/; metadata:author Actioner, created 2026-09-02; sid:2100204; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - PaperCut NG/MF UserList Auth Bypass via Home Page (CVE-2026-81578)"; flow:established, to_server; http_uri; content:"service=direct", fast_pattern; content:"UserList"; content:"/Home/"; classtype:web-application-attack; reference:cve,2026-81578; reference:url,rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/; metadata:author Actioner, created 2026-09-02; sid:2100205; rev:1;)
```

<!-- Audit: snort not available for compilation. Rules use Snort 3 underscore-notation sticky buffers (http_uri), http service protocol, and comma-delimited content modifiers per Snort 3 syntax. Structural review confirms balanced parentheses, all required fields (msg, sid, rev), semicolon termination, and flow keywords present. Six rules cover all combinations: ConfigEditor x {Error, Exception, Home} and UserList x {Error, Exception, Home}. -->

### YARA Rules: PaperCut Malicious Java Class Payload Detection

Two YARA rules targeting the malicious .class files deployed during exploitation -- one for OS command execution patterns in class files, and one for JDBC exploitation strings in class/JAR files.

**Compile**: yarac pass (exit 0) | **Confidence**: high (Rule 1), medium (Rule 2)

```yara
rule Exploit_PaperCut_Malicious_Class_Payload
{
    meta:
        description = "Detects malicious Java .class files deployed via PaperCut CVE-2026-82078 exploitation. Matches class files containing OS command execution patterns and reconnaissance strings observed in recovered payloads."
        author = "Actioner"
        date = "2026-09-02"
        reference = "https://www.huntress.com/blog/papercut-actively-exploited"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $magic = { CA FE BA BE }
        $runtime1 = "java/lang/Runtime" ascii
        $runtime2 = "getRuntime" ascii
        $exec = "exec" ascii
        $cmd1 = "whoami" ascii nocase
        $cmd2 = "cmd.exe" ascii nocase
        $cmd3 = "cmd /c" ascii nocase
        $cmd4 = "/bin/sh" ascii
        $cmd5 = "/bin/bash" ascii
        $cmd6 = "tasklist" ascii nocase
        $jdbc1 = "jdbc:derby:memory" ascii
        $jdbc2 = "jdbc:no:x" ascii
        $out_file = ".out" ascii
        $out_file2 = ".cmd" ascii

    condition:
        $magic at 0 and
        filesize < 50KB and
        ($runtime1 and $runtime2 and $exec) and
        (1 of ($cmd*) or 1 of ($jdbc*) or ($out_file and $out_file2))
}

rule Exploit_PaperCut_Derby_JDBC_Payload
{
    meta:
        description = "Detects Java class files or JAR archives containing JDBC exploitation strings used in PaperCut CVE-2026-82078 attacks to load malicious code via Derby in-memory database."
        author = "Actioner"
        date = "2026-09-02"
        reference = "https://horizon3.ai/attack-research/vulnerabilities/cve-2026-81578-cve-2026-82078/"
        severity = "high"
        tlp = "WHITE"

    strings:
        $magic_class = { CA FE BA BE }
        $magic_jar = { 50 4B 03 04 }
        $jdbc_pwn = "jdbc:derby:memory:pwn" ascii
        $jdbc_create = "create=true" ascii
        $values_cast = "VALUES CAST" ascii nocase
        $cafebabe_str = "cafebabe" ascii nocase
        $nashorn = "nashorn" ascii
        $scriptengine = "ScriptEngine" ascii

    condition:
        ($magic_class at 0 or $magic_jar at 0) and
        filesize < 5MB and
        (
            ($jdbc_pwn and $jdbc_create) or
            ($values_cast and $cafebabe_str) or
            ($nashorn and $scriptengine and 1 of ($jdbc*))
        )
}
```

<!-- Audit: yarac yara_papercut_exploit.yar /dev/null exit 0, both rules compile cleanly. Rule 1 requires Java class magic bytes at offset 0 + Runtime.exec() pattern + at least one recon command or JDBC string, constrained to small files (<50KB) matching observed payload sizes. Rule 2 targets JDBC exploitation artifacts in class/JAR files with Derby "pwn" database references or Nashorn engine usage alongside JDBC strings. -->

## Lessons Learned

1. **Tapestry framework authorization model is fundamentally fragile**: The ability to specify separate pages for rendering and action execution creates a structural authentication bypass when authorization is checked only against the rendered page. Any application using Apache Tapestry's direct request format should audit its authorization enforcement against the executed component, not the displayed page.

2. **Dynamic class loading without allowlists is a recurring RCE vector**: CVE-2026-82078 follows the same pattern seen in Log4Shell and other JNDI/JDBC injection attacks -- user-controllable input selecting which classes to load. Applications that accept driver names, class names, or JNDI paths from configuration should validate against strict allowlists.

3. **Print infrastructure remains a blind spot**: PaperCut servers often run with elevated privileges, handle sensitive data (print jobs can contain confidential documents), and are frequently exposed to the internet without adequate monitoring. The 47% unpatched figure and the similarity to the 2023 exploitation campaign suggest organizations have not internalized print management as a critical attack surface.

4. **Rapid patch bypass capability**: Attackers bypassed the first emergency patch within approximately 24 hours, necessitating two additional emergency patch releases. This underscores that patching alone is insufficient -- network segmentation and access controls must be the primary defense for internet-facing management interfaces.

## Sources

- [The Hacker News - Attackers Chain Two PaperCut Flaws](https://thehackernews.com/2026/08/attackers-chain-two-papercut-flaws-to.html) -- initial reporting on the chained exploitation with IOC details from PaperCut advisory
- [The Hacker News - PaperCut Zero-Day Exploited](https://thehackernews.com/2026/08/papercut-zero-day-exploited-in-attacks.html) -- early coverage of zero-day exploitation disclosure
- [Security Affairs - CISA KEV Addition](https://securityaffairs.com/198200/security/u-s-cisa-adds-papercut-ng-mf-flaws-to-its-known-exploited-vulnerabilities-catalog.html) -- CISA KEV catalog details, CVSS scores, remediation deadline, Huntress observations
- [The Register - PaperCut Under 0-Day Attack](https://www.theregister.com/security/2026/08/28/print-management-outfit-papercut-is-under-0-day-attack-and-its-drawing-customers-blood/5293168) -- early advisory reporting, mitigation guidance
- [Huntress - PaperCut Actively Exploited](https://www.huntress.com/blog/papercut-actively-exploited) -- primary technical analysis with file paths, base64 commands, .class payload recovery, process chains
- [Rapid7 - PaperCut NG/MF Critical Zero-Day](https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild/) -- Tapestry direct request URI patterns, ConfigEditor exploitation mechanism, JDBC chain details
- [Horizon3 - CVE-2026-81578 & CVE-2026-82078](https://horizon3.ai/attack-research/vulnerabilities/cve-2026-81578-cve-2026-82078/) -- technical IOCs, log signatures, file artifacts, detection guidance
- [SecurityWeek - More Details on PaperCut Vulnerabilities](https://www.securityweek.com/more-details-emerge-on-exploited-papercut-vulnerabilities/) -- affected version details, Huntress observations, patch timeline
- [BleepingComputer - PaperCut Emergency Patches](https://www.bleepingcomputer.com/news/security/papercut-releases-second-emergency-patch-for-exploited-flaws/) -- patch release timeline, version coverage, patch bypass details
- [Help Net Security - Remote Access Tools on PaperCut Servers](https://www.helpnetsecurity.com/2026/08/31/papercut-attack-remote-access-tools/) -- SimpleHelp and AnyDesk deployment details, persistence paths
- [Cybersecurity Dive - PaperCut Emergency Patches](https://www.cybersecuritydive.com/news/papercut-emergency-patches-threat-actors-chained-vulnerabilities/829184/) -- Huntress confirmation of 12 infected devices, 204 vulnerable instances, targeted sectors
- [PaperCut Official Security Advisory](https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/) -- vendor advisory with IOCs and mitigation guidance
- [eSentire Advisory](https://www.esentire.com/security-advisories/apercut-discloses-zero-day-vulnerabilities-cve-2026-82078-and-cve-2026-81578) -- MSSP advisory with CVE details and CVSS scores

---
*Report generated by Actioner*
