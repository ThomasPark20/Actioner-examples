# Technical Analysis Report: MariaDB Critical Galera Cluster Vulnerabilities — CVE-2026-49261 (CVSS 10.0) and Related CVEs (2026-06-08)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-08
Version: 1.1 REVISED

## Executive Summary

On 2026-05-27, MariaDB Foundation released corrective versions across all maintained long-term branches (10.6.27, 10.11.18, 11.4.12, 11.8.8) to address nine security vulnerabilities, three of which are rated high to critical severity. The most severe, CVE-2026-49261 (CVSS 10.0), is a parameter injection vulnerability in the Galera Cluster `wsrep_notify_cmd` notification mechanism that allows a malicious cluster peer to achieve unauthenticated remote command execution as the `mariadbd` process UID. Two related high-severity flaws — CVE-2026-48163 (CVSS 8.0) and CVE-2026-48165 (CVSS 8.0) — target additional Galera wsrep parameter handling in SST (State Snapshot Transfer) operations and runtime variable modification, respectively.

All three critical/high vulnerabilities stem from the same root cause class: failure to sanitize peer-supplied or user-supplied values before interpolating them into shell command lines or configuration files. No public proof-of-concept code or active exploitation has been reported as of the report date. The CVE-2026-49261 NVD entry remains in RESERVED status. Six additional CVEs (CVE-2026-3494, CVE-2026-44168, CVE-2026-44170, CVE-2026-44171, CVE-2026-44172, CVE-2026-44173) were fixed in the same release cycle, addressing audit plugin bypass, path traversal in mbstream, character encoding issues, and CONNECT REST argument injection.

Four Sigma detection rules are provided targeting the specific behavioral patterns of these vulnerabilities. Network-level (Snort/Suricata) and file-level (YARA) detections are not viable because the attacks occur through the Galera cluster's internal gcomm:// protocol and through SQL session variables rather than through inspectable network payloads or file artifacts.

**Viability assessment:** The MariaDB release notes (primary source) provide concrete technical details — specific parameter names, affected shell scripts/source files, and precise injection mechanisms. This is sufficient for behavioral detection rule generation at the process-creation and application-log layers. However, no PoC exploit code is publicly available, and the NVD entry is still RESERVED, which limits confidence in detection specificity.

## Background

MariaDB is a widely deployed open-source relational database management system, forked from MySQL. MariaDB Galera Cluster is a synchronous multi-master cluster implementation using the Galera library for Write-Set Replication (wsrep). Galera clusters use State Snapshot Transfer (SST) mechanisms (rsync, mariabackup, etc.) to synchronize new or rejoining nodes, and the `wsrep_notify_cmd` system variable to execute notification scripts when cluster membership or state changes occur.

The Galera replication layer introduces a unique attack surface: cluster peers exchange metadata (node names, addresses, credentials) that is consumed by shell scripts and configuration file generation on the receiving node. Prior vulnerabilities in this same attack surface include CVE-2020-15180 (wsrep_sst_method code injection) and CVE-2021-27928 (wsrep_provider command execution).

## Technical Analysis

### CVE-2026-49261 — wsrep_notify_cmd Parameter Injection (CVSS 10.0, MDEV-39721)

**Root cause:** The `wsrep_notify_cmd` notification mechanism in `wsrep_notify.cc` accepts peer-supplied values for `wsrep_node_name` and `wsrep_node_incoming_address` and interpolates them directly into the command line passed to the notification script without any sanitization of shell metacharacters.

**Attack vector:** A malicious Galera cluster peer (or an attacker who can inject themselves into the cluster via gcomm://) sets their `wsrep_node_name` or `wsrep_node_incoming_address` to a value containing shell metacharacters (e.g., `` `malicious_command` `` or `$(malicious_command)`). When the victim node's `wsrep_notify_cmd` script is invoked with these values, the injected commands execute as the `mariadbd` process UID.

**Fix:** Commit `ed8404a73f` (2026-05-22) — "reject shell-unsafe characters in joiner-supplied member fields" in `wsrep_notify.cc`.

**Severity rationale for CVSS 10.0:** The attack is network-exploitable, requires no authentication to the target MariaDB instance (only cluster membership or the ability to join the cluster), has no user interaction, and achieves arbitrary code execution with full impact on confidentiality, integrity, and availability.

### CVE-2026-48163 — SST rsync Parameter Injection on Donor Side (CVSS 8.0, MDEV-39648)

**Root cause:** The `wsrep_sst_rsync.sh` script failed to validate joiner-supplied `WSREP_SST_OPT_REMOTE_USER` and `WSREP_SST_OPT_REMOTE_PSWD` environment variable values before interpolating them into the donor-written `stunnel.conf` and the rsync magic file.

**Attack vector:** A malicious joiner node provides crafted credential values during SST that inject arbitrary content into the donor's stunnel configuration or rsync authentication file, potentially enabling command execution or configuration manipulation on the donor node.

**Fix:** Commit `dae315a7b2` (2026-05-18) — "apply safe() to joiner-supplied parameters" in `wsrep_sst_rsync.sh`.

### CVE-2026-48165 — Shell Command Execution via wsrep_sst_donor / wsrep_sst_receive_address (CVSS 8.0, MDEV-39676)

**Root cause:** The runtime-modifiable system variables `wsrep_sst_donor` and `wsrep_sst_receive_address` were not properly sanitized when used to construct shell commands. A user with SUPER privileges could set these variables to values containing shell metacharacters, achieving command execution as the `mariadbd` process UID.

**Attack vector:** An authenticated MariaDB user with SUPER privileges executes `SET GLOBAL wsrep_sst_donor='malicious; payload'` or `SET GLOBAL wsrep_sst_receive_address='malicious; payload'`. The unsanitized values are interpolated into a shell command during SST operations.

**Fix:** Commits `a9e2f7f648` (2026-05-21, "disallow global.wsrep_sst_donor=NULL again") and `13e6808f01` (2026-05-20, "Galera Cluster-peer > Donor command execution").

### Additional CVEs Fixed in Same Release

| CVE | CVSS | Description | MDEV |
|-----|------|-------------|------|
| CVE-2026-3494 | — | Audit plugin comment handling bypass — SQL statements prefixed with `--` or `#` comments bypass server_audit_events QUERY_DCL/DDL/DML filters | — |
| CVE-2026-44168 | 8.0 | Argument injection via unsanitized URLs in CONNECT REST Xcurl (Windows) | — |
| CVE-2026-44170 | 5.0 | Path traversal in mbstream utility | MDEV-39565 |
| CVE-2026-44171 | 6.3 | Incorrect handling of big5 encoding in mysql_real_escape_string() | — |
| CVE-2026-44172 | 5.0 | Missing FILE privilege checks in subqueries | — |
| CVE-2026-44173 | 5.0 | Unsafe usage of wsrep_notify_cmd parameters (related to CVE-2026-49261) | — |

## Indicators of Compromise (IOCs)

> **Note:** No file hashes, C2 domains, IP addresses, or traditional network IOCs exist for these vulnerabilities. All indicators are behavioral patterns at the process-creation and application-log layers. No active exploitation has been reported.

### Software/Version Level

| Component | Vulnerable Versions | Fixed Versions |
|-----------|---------------------|----------------|
| MariaDB Community Server 10.6.x | < 10.6.27 | 10.6.27 |
| MariaDB Community Server 10.11.x | < 10.11.18 | 10.11.18 |
| MariaDB Community Server 11.4.x | < 11.4.12 | 11.4.12 |
| MariaDB Community Server 11.8.x | < 11.8.8 | 11.8.8 |
| MariaDB Enterprise Server 11.8.x | < 11.8.6-4 | 11.8.6-4 |
| Galera library | < 26.4.27 | 26.4.27 |

### Behavioral Indicators (CVE-2026-49261)

- Child processes spawned by `mariadbd`/`mysqld` with command lines containing `wsrep_notify` AND shell metacharacters (`$(`, `` ` ``, `|`, `&&`, `;`)
- Galera cluster nodes with `wsrep_node_name` or `wsrep_node_incoming_address` values containing shell metacharacters
- Unexpected processes running as the `mysql` user on Galera cluster nodes

### Behavioral Indicators (CVE-2026-48163)

- SST processes (`wsrep_sst_rsync`, `wsrep_sst_*`) spawned by `mariadbd` with shell injection characters in command lines
- Modified `stunnel.conf` files on donor nodes containing unexpected directives

### Behavioral Indicators (CVE-2026-48165)

- `SET GLOBAL wsrep_sst_donor` or `SET GLOBAL wsrep_sst_receive_address` SQL statements containing shell metacharacters in MariaDB query/audit logs
- Process execution under the `mysql` user context following SST variable modification

### Behavioral Indicators (CVE-2026-3494)

- SQL queries beginning with `--` or `#` comment prefixes followed immediately by DDL/DCL/DML keywords in query proxy logs (these would NOT appear in MariaDB's own audit logs due to the bypass)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | CVE-2026-49261: Exploitation of MariaDB Galera cluster communication to inject commands via malicious node metadata. CVE-2026-48163: Exploitation of SST mechanism via malicious joiner node. |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | All three Galera CVEs result in shell command execution via injection into shell command construction or shell script parameters. |
| T1611 | Escape to Host | CVE-2026-48165: Authenticated user with SUPER privilege escapes the database layer to achieve OS-level command execution as the mariadbd process UID. |
| T1070 | Indicator Removal | CVE-2026-3494: Attacker bypasses MariaDB audit plugin logging by prefixing SQL statements with comment characters. |

## Detection & Remediation

### Immediate Detection

**Check MariaDB version:**
```bash
mysql -e "SELECT VERSION();"
# Or via package manager:
dpkg -l | grep mariadb-server
rpm -qa | grep MariaDB-server
```

**Check if Galera cluster is active (only Galera users are affected by the critical CVEs):**
```sql
SHOW STATUS LIKE 'wsrep_cluster_size';
SHOW VARIABLES LIKE 'wsrep_on';
```

**Review wsrep_notify_cmd configuration:**
```sql
SHOW VARIABLES LIKE 'wsrep_notify_cmd';
```

**Review wsrep node metadata for injection indicators:**
```sql
SHOW STATUS LIKE 'wsrep_incoming_addresses';
SHOW VARIABLES LIKE 'wsrep_node_name';
SHOW VARIABLES LIKE 'wsrep_node_incoming_address';
```
Look for values containing shell metacharacters: `$`, `` ` ``, `|`, `&`, `;`, `>`, `<`.

**Review MariaDB error log for unusual process execution:**
```bash
grep -iE "wsrep_notify|wsrep_sst" /var/log/mysql/error.log | grep -E '[$`|;&><]'
```

### Remediation

1. **Patch immediately:** Upgrade to MariaDB 10.6.27, 10.11.18, 11.4.12, or 11.8.8 (depending on your branch). Enterprise Server users should upgrade to 11.8.6-4.
2. **Restrict Galera cluster membership:** Ensure gcomm:// cluster URIs use authentication and TLS. Restrict network access to Galera communication ports (4567 TCP/UDP for cluster communication, 4568 TCP for IST, 4444 TCP for SST) to known cluster nodes only.
3. **Audit SUPER privilege grants:** Review which users hold SUPER privileges and revoke where not strictly necessary. CVE-2026-48165 requires SUPER privileges.
4. **Enable query audit logging via a proxy:** Since CVE-2026-3494 bypasses the built-in audit plugin, consider using an external query proxy (e.g., ProxySQL, MaxScale) for audit logging that is not subject to the comment-prefix bypass.
5. **Monitor wsrep_notify_cmd script:** If you use a wsrep notification script, ensure it is read-only and owned by root, not writable by the mysql user.

### Long-Term Hardening

- Deploy MariaDB Galera Cluster behind network segmentation with strict firewall rules limiting cluster communication to known node IPs.
- Use TLS for all Galera intra-cluster communication (`wsrep_provider_options="socket.ssl=true"`).
- Implement process monitoring on database servers to detect unexpected child processes spawned by `mariadbd`.
- Evaluate the security posture of your chosen SST method (`rsync`, `mariabackup`, etc.) and ensure all SST-related scripts are updated to the patched versions.
- Rotate all cluster credentials if exploitation is suspected.

## Detection Rules

These detections target the specific behavioral patterns from CVE-2026-49261, CVE-2026-48163, CVE-2026-48165, and CVE-2026-3494. The Sigma rules key on Linux process creation logs (Sysmon for Linux, auditd, or EDR telemetry) and MariaDB application/query logs. No network-level (Snort/Suricata) or file-level (YARA) rules are provided because: (1) Galera cluster communication uses the gcomm:// protocol which does not lend itself to signature-based network inspection, and (2) no file-level artifacts (hashes, dropped files) are associated with these vulnerabilities.

### Sigma: MariaDB Galera wsrep_notify_cmd Parameter Injection (CVE-2026-49261)

Detects child processes spawned by mariadbd/mysqld related to wsrep notification commands containing shell injection metacharacters, indicating potential exploitation of the wsrep_node_name / wsrep_node_incoming_address parameter injection vulnerability.

**Status:** compile pass | confidence: medium
<!-- revision: v1.1 — removed --status (too generic), narrowed metacharacters to $( ` && only (removed | ; > < which match legitimate shell operations), added wsrep-notify and wsrep-specific flags --members/--index. sigma check 0 errors; sigma convert splunk OK; sigma convert log_scale OK. -->
<!-- audit: sigma check 0 errors; sigma convert splunk OK; sigma convert log_scale OK. Logsource category:process_creation product:linux requires Sysmon for Linux, auditd with execve logging, or EDR process telemetry. FP risk: reduced after narrowing metacharacters to injection-specific patterns only. The three-way AND condition (parent + notify keyword + metacharacter) constrains FP surface. -->

```yaml
title: MariaDB Galera wsrep_notify_cmd Parameter Injection via Malicious Node Name (CVE-2026-49261)
id: f2bc199f-1cb6-4d4b-a082-ae896e33e4c1
status: experimental
description: |
    Detects potential exploitation of CVE-2026-49261 where a malicious Galera cluster peer injects
    shell metacharacters through wsrep_node_name or wsrep_node_incoming_address values that are
    interpolated unsanitized into the wsrep_notify_cmd command line, enabling arbitrary command
    execution as the mariadbd process UID.
references:
    - https://securityonline.info/mariadb-security-flaw-cvss-10/
    - https://mariadb.com/docs/release-notes/community-server/10.6/10.6.27
    - https://mariadb.org/mariadb-community-server-corrective-releases/
author: Actioner
date: 2026/06/08
tags:
    - attack.t1059.004
    - attack.t1190
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/mariadbd'
            - '/mysqld'
    selection_notify_script:
        CommandLine|contains:
            - 'wsrep_notify'
            - 'wsrep-notify'
            - '--members'
            - '--index'
    selection_injection_indicators:
        CommandLine|contains:
            - '$('
            - '`'
            - '&&'
    condition: selection_parent and selection_notify_script and selection_injection_indicators
falsepositives:
    - Custom wsrep notification scripts that use subshell expansion or command chaining in their arguments
level: high
```

**Splunk SPL:**
```spl
(ParentImage="*/mariadbd" OR ParentImage="*/mysqld") (CommandLine="*wsrep_notify*" OR CommandLine="*wsrep-notify*" OR CommandLine="*--members*" OR CommandLine="*--index*") (CommandLine="*$(*" OR CommandLine="*`*" OR CommandLine="*&&*")
```

**CrowdStrike LogScale:**
```
(ParentImage=/\/mariadbd$/i or ParentImage=/\/mysqld$/i) (CommandLine=/wsrep_notify/i or CommandLine=/wsrep-notify/i or CommandLine=/--members/i or CommandLine=/--index/i) (CommandLine=/\$\(/i or CommandLine=/`/i or CommandLine=/&&/i)
```

---

### Sigma: MariaDB Galera SST rsync Parameter Injection (CVE-2026-48163)

Detects SST-related processes spawned by mariadbd with shell injection metacharacters in their command lines, indicating potential exploitation of the wsrep_sst_rsync parameter injection via malicious joiner-supplied credential values.

**Status:** compile pass | confidence: medium
<!-- audit: sigma check 0 errors; sigma convert splunk OK; sigma convert log_scale OK. Same logsource requirements as above. FP risk: legitimate SST operations do not normally include shell metacharacters in credential parameters. -->

```yaml
title: MariaDB Galera SST rsync Parameter Injection via Joiner-Supplied Credentials (CVE-2026-48163)
id: 7db3aa0c-aa8e-4116-ab36-96cc5cea8daf
status: experimental
description: |
    Detects potential exploitation of CVE-2026-48163 (MDEV-39648) where a malicious Galera cluster
    joiner injects shell metacharacters through WSREP_SST_OPT_REMOTE_USER or
    WSREP_SST_OPT_REMOTE_PSWD values that are interpolated unsanitized into the donor-side
    stunnel.conf or rsync magic file during State Snapshot Transfer operations.
references:
    - https://securityonline.info/mariadb-security-flaw-cvss-10/
    - https://mariadb.com/docs/release-notes/community-server/10.6/10.6.27
    - https://mariadb.org/mariadb-community-server-corrective-releases/
author: Actioner
date: 2026/06/08
tags:
    - attack.t1059.004
    - attack.t1190
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/mariadbd'
            - '/mysqld'
    selection_sst_process:
        CommandLine|contains:
            - 'wsrep_sst_rsync'
            - 'wsrep_sst_'
    selection_injection:
        CommandLine|contains:
            - '$('
            - '`'
            - '|'
            - ';'
    condition: selection_parent and selection_sst_process and selection_injection
falsepositives:
    - Legitimate SST operations with unusual but benign parameter values
level: high
```

**Splunk SPL:**
```spl
ParentImage IN ("*/mariadbd", "*/mysqld") CommandLine IN ("*wsrep_sst_rsync*", "*wsrep_sst_*") CommandLine IN ("*$(*", "*`*", "*|*", "*;*")
```

**CrowdStrike LogScale:**
```
ParentImage=/\/mariadbd$/i or ParentImage=/\/mysqld$/i CommandLine=/wsrep_sst_rsync/i or CommandLine=/wsrep_sst_/i CommandLine=/\$\(/i or CommandLine=/`/i or CommandLine=/\|/i or CommandLine=/;/i
```

---

### Sigma: MariaDB Galera Shell Execution via wsrep_sst_donor Variable Modification (CVE-2026-48165)

Detects SET GLOBAL statements targeting wsrep_sst_donor or wsrep_sst_receive_address with values containing shell metacharacters in MariaDB query/audit logs, indicating potential exploitation by a privileged user to achieve OS-level command execution.

**Status:** compile pass | confidence: medium-high
<!-- audit: sigma check 0 errors; sigma convert splunk OK; sigma convert log_scale OK. Logsource product:mysql category:application requires MariaDB general query log, audit plugin, or proxy-based query logging. FP risk: low — legitimate wsrep_sst_donor values are hostname/IP strings and should never contain shell metacharacters. -->

```yaml
title: MariaDB Galera Shell Command Execution via wsrep_sst_donor or wsrep_sst_receive_address Modification (CVE-2026-48165)
id: 0e309a4b-c521-42d7-848a-469509fd3dd2
status: experimental
description: |
    Detects potential exploitation of CVE-2026-48165 (MDEV-39676) where a privileged MariaDB user
    with SUPER privileges modifies the wsrep_sst_donor or wsrep_sst_receive_address system variables
    at runtime to inject shell commands that execute as the mariadbd process UID. This rule monitors
    MariaDB logs or query audit logs for SET GLOBAL statements targeting these variables with
    suspicious payloads containing shell metacharacters.
references:
    - https://securityonline.info/mariadb-security-flaw-cvss-10/
    - https://mariadb.com/docs/release-notes/community-server/10.6/10.6.27
    - https://mariadb.org/mariadb-community-server-corrective-releases/
author: Actioner
date: 2026/06/08
tags:
    - attack.t1059.004
    - attack.t1548.003
logsource:
    product: mysql
    category: application
detection:
    selection_set_global:
        query|contains|all:
            - 'SET'
            - 'GLOBAL'
        query|contains:
            - 'wsrep_sst_donor'
            - 'wsrep_sst_receive_address'
    filter_injection:
        query|contains:
            - '$('
            - '`'
            - '|'
            - ';'
            - '&&'
    condition: selection_set_global and filter_injection
falsepositives:
    - Database administrators setting SST donor with values that coincidentally contain shell metacharacters
level: critical
```

**Splunk SPL:**
```spl
query="*SET*" query="*GLOBAL*" query IN ("*wsrep_sst_donor*", "*wsrep_sst_receive_address*") query IN ("*$(*", "*`*", "*|*", "*;*", "*&&*")
```

**CrowdStrike LogScale:**
```
query=/SET/i query=/GLOBAL/i query=/wsrep_sst_donor/i or query=/wsrep_sst_receive_address/i query=/\$\(/i or query=/`/i or query=/\|/i or query=/;/i or query=/&&/i
```

---

### Sigma: MariaDB Audit Plugin Bypass via SQL Comment Prefix (CVE-2026-3494)

Detects SQL queries that begin with comment prefixes (`--` or `#`) followed by sensitive DDL/DCL/DML operations, which exploit the audit plugin comment handling bypass to evade query logging.

**Status:** compile pass | confidence: medium
<!-- audit: sigma check 0 errors; sigma convert splunk OK; sigma convert log_scale OK. This rule must be deployed on a query proxy or network tap that captures raw SQL — the MariaDB audit plugin itself will NOT log these queries due to the bypass. FP risk: moderate — some ORMs and migration tools prepend comments to queries. The regex anchoring (^) constrains to queries that START with comments. -->

```yaml
title: MariaDB Audit Plugin Bypass via SQL Comment Prefix (CVE-2026-3494)
id: 7f2f97ac-8082-41db-b03d-372486c85936
status: experimental
description: |
    Detects potential exploitation of CVE-2026-3494 where an authenticated MariaDB user prefixes SQL
    statements with double-hyphen (--) or hash (#) style comments to bypass the server audit plugin
    logging when server_audit_events is configured with QUERY_DCL, QUERY_DDL, or QUERY_DML filtering.
    This rule looks for suspicious SQL queries in application or proxy logs that begin with comment
    characters followed by sensitive DDL/DCL/DML operations.
references:
    - https://securityonline.info/mariadb-security-flaw-cvss-10/
    - https://mariadb.com/docs/release-notes/community-server/10.6/10.6.27
    - https://www.tenable.com/cve/CVE-2026-3494
author: Actioner
date: 2026/06/08
tags:
    - attack.t1070
logsource:
    product: mysql
    category: application
detection:
    selection_comment_prefix:
        query|re: '^(--|#)\s*(DROP|ALTER|CREATE|GRANT|REVOKE|INSERT|UPDATE|DELETE|TRUNCATE)'
    condition: selection_comment_prefix
falsepositives:
    - SQL scripts or ORMs that prepend comments to queries for tracing purposes
    - Database migration tools that use comments before DDL statements
level: medium
```

**Splunk SPL:**
```spl
* | regex query="^(--|#)\\s*(DROP|ALTER|CREATE|GRANT|REVOKE|INSERT|UPDATE|DELETE|TRUNCATE)"
```

**CrowdStrike LogScale:**
```
query=/^(--|#)\s*(DROP|ALTER|CREATE|GRANT|REVOKE|INSERT|UPDATE|DELETE|TRUNCATE)/
```

---

### Rules NOT Generated — Rationale

**Snort / Suricata (network-level):** Not generated. The Galera cluster vulnerabilities (CVE-2026-49261, CVE-2026-48163) occur through the gcomm:// protocol, which is a proprietary Galera communication protocol that does not lend itself to content-based signature inspection. CVE-2026-48165 occurs through SQL session variable modification over the MySQL wire protocol, but the injection payload (SET GLOBAL wsrep_sst_donor=...) is syntactically identical to legitimate configuration changes, making network-level detection impractical without deep MySQL protocol parsing and state tracking that exceeds rule-based capabilities.

**YARA (file-level):** Not generated. No file artifacts (malicious binaries, dropped files, webshells) are associated with these vulnerabilities. The attacks result in command execution through parameter injection, not through file delivery.

## Sources

- [SecurityOnline: Millions of Servers At Risk: Crucial MariaDB Flaw Carries Maximum 10.0 CVSS Score](https://securityonline.info/mariadb-security-flaw-cvss-10/) — Published 2026-06-07. Original reporting article. Re-fetched and confirmed accessible 2026-06-08.
- [MariaDB 10.6.27 Release Notes](https://mariadb.com/docs/release-notes/community-server/10.6/10.6.27) — Primary source. Contains MDEV numbers, vulnerability descriptions, CVSS scores, and commit references.
- [MariaDB 11.4.12 Release Notes](https://mariadb.com/docs/release-notes/community-server/11.4/11.4.12) — Confirms same CVE fixes across branches.
- [MariaDB 10.6.27 Changelog](https://mariadb.com/docs/release-notes/community-server/changelogs/10.6/10.6.27) — Detailed changelog with commit hashes and affected files.
- [MariaDB Community Server Corrective Releases](https://mariadb.org/mariadb-community-server-corrective-releases/) — MariaDB Foundation announcement.
- [OffSeq Threat Radar: Security Update for MariaDB](https://radar.offseq.com/threat/security-update-for-mariadb-f4e253c4) — Third-party advisory aggregation listing all nine CVEs.
- [IntegSec: CVE-2026-32710 MariaDB Server Crash Flaw](https://integsec.com/blog/cve-2026-32710-mariadb-server-crash-flaw-what-it-means-for-your-business-and-how-to-respond) — Related MariaDB JSON schema vulnerability context.
- [Tenable: CVE-2026-3494](https://www.tenable.com/cve/CVE-2026-3494) — Audit plugin bypass details.
- [NVD: CVE-2026-49261](https://nvd.nist.gov/vuln/detail/CVE-2026-49261) — Status: RESERVED (not yet populated as of 2026-06-08).
- [MariaDB Enterprise Server 11.8.6-4 Release Notes](https://mariadb.com/docs/release-notes/enterprise-server/11.8/11.8.6-4) — Enterprise version fix confirmation.
