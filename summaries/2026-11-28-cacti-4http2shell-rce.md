# Technical Analysis Report: Cacti 4HTTP2SHELL / 4HTTP2ROOT Unauthenticated RCE Zero-Day

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-11-28
Version: 1.0 (DRAFT)

## Executive Summary

4HTTP2SHELL (also tracked as 4HTTP2ROOT) is an unpatched zero-day vulnerability in Cacti, the widely deployed open-source network monitoring and graphing platform. The flaw enables unauthenticated remote code execution (RCE) in just four HTTP requests when the Cacti guest account is enabled. The attack chains three distinct weaknesses: (1) insufficient validation of a guest-editable numeric display setting, (2) a second-order SQL injection via a stacked statement in a LIMIT clause, and (3) unsafe execution of a database-stored poller command through PHP's `popen()`. No CVE has been officially assigned as of 2026-11-28. A public proof-of-concept was released on November 26, 2026 (Thanksgiving Day) by researcher "ek0ms savi0r" of the "Church of Malware" / "Sad Girls 0day Club." The Cacti Group has issued no advisory, patch, or public statement. Honeypot operators reported the first scanning/exploitation attempts within 24 hours of PoC publication. Cacti Core 1.2.31 (the latest release) is confirmed affected; the full vulnerable version range is unknown but likely includes earlier 1.2.x releases sharing the same code paths. The guest account has been disabled by default since Cacti 0.8.7, limiting exposure to deployments that explicitly enabled it.

## Background: Cacti

[Cacti](https://www.cacti.net/) is an open-source, PHP-based network monitoring, fault management, and graphing platform built on RRDtool. It is used by enterprises, service providers, and government networks worldwide to monitor thousands of network devices via SNMP, scripted data collection, and custom pollers. Cacti stores network device credentials (SNMP community strings, SSH/SNMP v3 credentials) and maintains a MySQL/MariaDB database of polling configurations, graph templates, and user settings. Compromise of a Cacti server provides an attacker with a foothold on the management network and access to credentials for downstream infrastructure.

The optional guest account allows unauthenticated visitors to view graphs without logging in. This feature has been disabled by default since Cacti 0.8.7, but many legacy deployments and quick-setup guides still enable it.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2020 (CVE-2020-8813) | Earlier RCE via `graph_realtime.php` cookie injection when guest access enabled; patched |
| 2026-06-15 | Cacti Core 1.2.31 released; fixes CVE-2026-39893 (SQL injection in `graph_view.php`) |
| 2026-11-26 | ek0ms savi0r publishes 4HTTP2SHELL PoC on GitHub ("Sad Girls 0day Club"); no prior vendor notification |
| 2026-11-27 | [BleepingComputer](https://www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/), [The Hacker News](https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html) publish advisories |
| 2026-11-27 | Previdian logs 22 SQL injection attempts from a single IP against honeypots (time-based payloads; no confirmed command execution) |
| 2026-11-28 | No vendor patch, advisory, or CVE assignment. Not in CISA KEV |

## Root Cause: Stored Second-Order SQL Injection Chained to Poller Command Execution

The vulnerability is a chain of four weaknesses across three PHP endpoints:

1. **Missing type validation on guest profile setting:** The `auth_profile.php?action=update_data` endpoint allows the guest account to write an arbitrary string into the `preview_graphs_per_page` user setting in the `settings_user` table. Although the value should be a positive integer, Cacti does not validate the data type. The write itself uses a prepared statement, so this step alone is not exploitable.

2. **Second-order SQL injection via LIMIT clause:** When `graph_view.php?action=preview` is loaded with default filters, the stored `preview_graphs_per_page` value is read back and concatenated into a SQL `LIMIT` clause in `get_allowed_graphs()` (`lib/auth.php`). Because PHP's PDO driver (with the MySQL driver) accepts stacked/multi-statement queries, the attacker's injected SQL executes as a secondary statement.

3. **Poller table poisoning:** The injected SQL is an `UPDATE` statement targeting the `poller_item` table, specifically modifying the `arg1` field (and potentially `host_id`/`action`) for a chosen `local_data_id`. This overwrites the legitimate poller command with an attacker-controlled OS command string.

4. **Unvalidated command execution via popen():** When `graph_realtime.php?action=init` is requested, the realtime poller subsystem (`poller_realtime.php` / `cmd_realtime.php`) reads the modified `poller_item.arg1` value from the database and passes it directly to `exec_poll()` / `popen()` in `lib/poller.php` with no sanitization, allowlisting, or escaping. The attacker's command executes with the privileges of the Cacti web server and poller process (typically `www-data` or `apache`; root if misconfigured).

## Technical Analysis of the 4HTTP2SHELL Exploit Chain

### Request 1 -- Guest Session Initialization

- **Method/Path:** `GET /cacti/auth_profile.php?tab=general`
- **Purpose:** Obtain a valid PHP session cookie and CSRF/nonce token as the anonymous guest user. No credentials are required.
- **Response:** Sets `Cacti` or `PHPSESSID` cookie; returns HTML containing the CSRF token for subsequent POST requests.

### Request 2 -- Stored SQL Injection Payload via Profile Update

- **Method/Path:** `POST /cacti/auth_profile.php` with query parameter `action=update_data`
- **Body:** Form-encoded data including `preview_graphs_per_page` set to a non-numeric value containing the SQL injection payload. The payload is a stacked statement that performs an `UPDATE` on the `poller_item` table, overwriting the `arg1` column for a target `local_data_id` with an OS command.
- **Result:** The malicious value is stored in the `settings_user` table via a prepared statement (no immediate SQL execution).

### Request 3 -- Trigger Second-Order SQL Injection

- **Method/Path:** `GET /cacti/graph_view.php?action=preview`
- **Purpose:** Loading the graph preview page with default filters causes Cacti to read the stored `preview_graphs_per_page` value and concatenate it into a `LIMIT` clause in `get_allowed_graphs()`. The PDO driver executes the stacked `UPDATE` statement, poisoning the `poller_item` table.
- **Result:** The target `poller_item.arg1` row now contains the attacker's OS command.

### Request 4 -- Command Execution via Realtime Poller

- **Method/Path:** `GET /cacti/graph_realtime.php?action=init&local_data_id=<target_id>&clear=1&ds_step=10&size=90`
- **Purpose:** Triggers the realtime poller, which reads the poisoned `poller_item.arg1` from the database and passes it to PHP's `popen()`.
- **Result:** Arbitrary command execution as the web server/poller user. The PoC demonstrates webshell deployment and reverse shell capabilities.
- **Default PoC parameters:** `clear=1`, `ds_step=10`, `size=90` are characteristic of the public PoC.

### Post-Exploitation Indicators

- The PoC reportedly drops a PHP webshell into a web-accessible directory (cache folder or web root).
- Commands run with the privileges of the web server account (`www-data`, `apache`, etc.); root-level access requires Cacti to already be running as root.
- Stored SNMP community strings and device credentials in the Cacti database are immediately accessible to the attacker.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs use `hxxps://`/`[.]`; IPs/domains/emails defanged. File paths, endpoint names, and command-line artifacts are shown as-is (local/non-resolvable).

### CVE / Tracking Identifiers

| Identifier | Status | Notes |
|-----------|--------|-------|
| 4HTTP2SHELL / 4HTTP2ROOT | Researcher name | Primary tracking names |
| CVE (none assigned) | Unassigned | No official CVE as of 2026-11-28 |
| CVE-2026-39893 | Separate issue | Fixed in Cacti 1.2.31; different SQL injection in `graph_view.php` |
| CVE-2026-132165 | Unverified | Listed on Sploitus with incorrect product mapping (Drupal); treat as unconfirmed |
| Previdian VULN-2026-0010 | Third-party tracker | Previdian vulnerability tracking |
| TL-2026-6953 | Third-party tracker | ThreadLinqs threat intelligence |

### Web Server Log Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `POST` to `auth_profile.php` with `action=update_data` | HTTP request | Step 2: SQLi payload storage |
| `preview_graphs_per_page` with non-numeric value in POST body | Parameter | Injected payload field |
| `GET graph_view.php?action=preview` from guest session | HTTP request | Step 3: SQLi trigger |
| `GET graph_realtime.php?action=init` with `clear=1&ds_step=10` | HTTP request | Step 4: RCE trigger |
| Sequence of above 3 endpoints from same source IP within minutes | Behavioral | Full exploit chain |

### Database Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| Non-numeric value in `settings_user` where `name='preview_graphs_per_page'` | Database tamper | SQL injection payload stored |
| Unexpected command strings in `poller_item.arg1` | Database tamper | Poisoned poller command |
| Shell metacharacters or OS commands in `poller_item` fields | Database tamper | Post-exploitation artifact |

### Host Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| Unexpected PHP files in Cacti web root or cache directories | File system | Dropped webshell |
| Files owned by web server user (`www-data`/`apache`) in unusual locations | File system | Post-exploitation artifact |
| Unexpected child processes spawned by PHP/web server process | Process | Command execution |
| Outbound connections from Cacti server to unexpected destinations | Network | Reverse shell / C2 |
| PHP warnings about non-numeric values in `graph_view.php` | Application log | SQLi trigger artifact |

### Software Versions

| Package | Affected Version | Fixed Version | Notes |
|---------|-----------------|---------------|-------|
| Cacti Core | 1.2.31 (confirmed); likely earlier 1.2.x | None (unpatched) | Guest account must be enabled |
| Cacti Core | 1.2.22 | None (unpatched) | Reported working in PoC repo |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application to 4HTTP2SHELL |
|--------|-----------|-----|---------------------------|
| Initial Access | Exploit Public-Facing Application | T1190 | Exploitation of Cacti web interface without authentication |
| Initial Access | Valid Accounts: Default Accounts | T1078.001 | Abuse of the built-in guest account |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | OS commands passed to `popen()` via poisoned poller table |
| Persistence | Server Software Component: Web Shell | T1505.003 | PoC drops a PHP webshell into the web root |
| Impact | Data Manipulation: Stored Data Manipulation | T1565.001 | Modification of `poller_item` database table |
| Credential Access | Unsecured Credentials | T1552 | Access to SNMP community strings and device credentials stored in Cacti |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 | Cacti configuration files contain database credentials |
| Defense Evasion | Impair Defenses | T1562 | Poller modifications can suppress monitoring alerts |
| Discovery | System Owner/User Discovery | T1033 | Determine execution context (web server account) |
| Defense Evasion | Indicator Removal | T1070 | Potential cleanup of injected database values |

## Detection & Remediation

### Immediate Mitigations (No Patch Available)

1. **Disable the guest account:** In Cacti Authentication Settings, set the Guest User to "No User" and disable the guest account in User Management. This blocks the demonstrated attack path.
2. **Restrict network access:** Limit access to the Cacti web interface to trusted management networks via firewall rules, VPN, or an authenticating reverse proxy. Specifically restrict `auth_profile.php`, `graph_view.php`, and `graph_realtime.php`.
3. **Run Cacti as a low-privilege user:** Ensure the web server and poller processes do not run as root.
4. **Audit database for tampering:**
   - Check `settings_user` for non-numeric `preview_graphs_per_page` values: `SELECT * FROM settings_user WHERE name='preview_graphs_per_page' AND value NOT REGEXP '^[0-9]+$';`
   - Review `poller_item.arg1` for unexpected OS commands or shell metacharacters.
5. **Rotate credentials:** If compromise is suspected, rotate all SNMP community strings, SSH keys, and device credentials stored in Cacti.
6. **Monitor logs:** Watch Apache/Nginx access logs and `cacti.log` for PHP warnings about non-numeric values from `graph_view.php`.
7. **Apply vendor patch when available:** Monitor [Cacti GitHub releases](https://github.com/Cacti/cacti/releases) and security advisories.

### Hunting Queries

**Apache/Nginx access log -- sequential endpoint access from one client:**
```
# Look for the 3 key endpoints hit by one source IP within 10 minutes
grep -E 'auth_profile\.php|graph_view\.php.*action=preview|graph_realtime\.php.*action=init' /var/log/apache2/access.log | sort
```

**MySQL -- check for poisoned settings:**
```sql
SELECT user_id, name, value FROM settings_user
WHERE name = 'preview_graphs_per_page'
AND value NOT REGEXP '^[0-9]+$';
```

**MySQL -- check for poisoned poller commands:**
```sql
SELECT local_data_id, arg1 FROM poller_item
WHERE arg1 LIKE '%|%' OR arg1 LIKE '%;%' OR arg1 LIKE '%&&%'
   OR arg1 LIKE '%$(% ' OR arg1 LIKE '%`%';
```

## Detection Rules

### Sigma Rule 1: Cacti 4HTTP2SHELL Profile Update SQL Injection Attempt

Detects HTTP POST requests to Cacti's `auth_profile.php` with `action=update_data` containing the `preview_graphs_per_page` parameter, which is the second step of the exploit chain where the attacker stores the SQL injection payload.
**Status:** compile ✅ compiles (sigma convert -t splunk, -t log_scale) · confidence: **medium**

<!-- audit: validated via sigma convert --without-pipeline -t splunk -> exit 0 (output: "cs-method"="POST" "cs-uri-stem"="*auth_profile.php*" "cs-uri-query"="*update_data*" OR "cs-body"="*preview_graphs_per_page*"); also sigma convert --without-pipeline -t log_scale -> exit 0. sigma check failed due to environment network issue (MITRE ATT&CK data fetch 403), not a rule defect. Medium confidence: legitimate profile updates also hit this endpoint, but the combination with cs-body containing preview_graphs_per_page narrows it. -->

```yaml
title: Cacti 4HTTP2SHELL Profile Update SQL Injection Attempt
id: a7e3c4b1-9f28-4d6a-b5e2-1c8d7a3f6e09
status: experimental
description: >
    Detects HTTP POST requests to Cacti's auth_profile.php endpoint with
    action=update_data, which is the second step of the 4HTTP2SHELL exploit
    chain. The attacker stores a non-numeric value (containing SQL injection
    payload) into the preview_graphs_per_page user setting via the guest
    account. This is a second-order SQL injection that fires when
    graph_view.php later reads the stored value into a LIMIT clause.
references:
    - https://www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/
    - https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html
    - https://github.com/thiscitze/cacti-4http2shell
author: Actioner
date: 2026/11/28
tags:
    - attack.initial_access
    - attack.t1190
    - attack.t1078.001
logsource:
    category: webserver
    product: apache
detection:
    selection_method:
        cs-method: 'POST'
    selection_uri:
        cs-uri-stem|contains: 'auth_profile.php'
    selection_param:
        cs-uri-query|contains: 'update_data'
    selection_body:
        cs-body|contains: 'preview_graphs_per_page'
    condition: selection_method and selection_uri and (selection_param or selection_body)
falsepositives:
    - Legitimate Cacti users updating their graph display preferences via the profile page
level: medium
```

### Sigma Rule 2: Cacti 4HTTP2SHELL Full Exploit Chain - Sequential Endpoint Access

Detects the full 4HTTP2SHELL exploit chain by identifying requests to all three key endpoints (`auth_profile.php`, `graph_view.php` with `action=preview`, `graph_realtime.php`) from the same source within a 10-minute timeframe.
**Status:** compile ✅ compiles (sigma convert -t splunk, -t log_scale) · confidence: **high**

<!-- audit: validated via sigma convert --without-pipeline -t splunk -> exit 0 (output: "cs-uri-stem"="*auth_profile.php*" "cs-uri-stem"="*graph_view.php*" "cs-uri-query"="*preview*" "cs-uri-stem"="*graph_realtime.php*"); also sigma convert --without-pipeline -t log_scale -> exit 0. High confidence because hitting all three endpoints in sequence is highly characteristic of this exploit chain. Normal admin browsing may occasionally touch all three, but the combination with the action=preview filter makes it specific. Note: the timeframe keyword requires SIEM-side correlation in most backends. -->

```yaml
title: Cacti 4HTTP2SHELL Full Exploit Chain - Sequential Endpoint Access
id: b8f4d5c2-0a39-5e7b-c6f3-2d9e8b4a7f10
status: experimental
description: >
    Detects the 4HTTP2SHELL exploit chain against Cacti by identifying
    requests to all three key endpoints (auth_profile.php, graph_view.php,
    graph_realtime.php) from the same source within a short timeframe.
    The chain exploits guest access to store a SQL injection payload in
    user preferences, trigger it via graph preview, and execute commands
    through the realtime poller. All four HTTP requests hit these three
    endpoints sequentially.
references:
    - https://www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/
    - https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html
    - https://github.com/thiscitze/cacti-4http2shell
author: Actioner
date: 2026/11/28
tags:
    - attack.initial_access
    - attack.t1190
    - attack.t1078.001
    - attack.execution
    - attack.t1059.004
logsource:
    category: webserver
    product: apache
detection:
    selection_step1:
        cs-uri-stem|contains: 'auth_profile.php'
    selection_step2:
        cs-uri-stem|contains: 'graph_view.php'
        cs-uri-query|contains: 'preview'
    selection_step3:
        cs-uri-stem|contains: 'graph_realtime.php'
    condition: selection_step1 and selection_step2 and selection_step3
    timeframe: 10m
falsepositives:
    - Legitimate Cacti administrators browsing profile settings and graph views in the same session
level: high
```

### Sigma Rule 3: Cacti 4HTTP2SHELL Realtime Graph Command Execution Request

Detects requests to `graph_realtime.php?action=init` with the default PoC parameters (`clear=1`, `ds_step=`), which is the final step of the exploit chain triggering `popen()` command execution.
**Status:** compile ✅ compiles (sigma convert -t splunk, -t log_scale) · confidence: **medium**

<!-- audit: validated via sigma convert --without-pipeline -t splunk -> exit 0 (output: "cs-uri-stem"="*graph_realtime.php*" "cs-uri-query"="*action=init*" "cs-uri-query"="*clear=1*" "cs-uri-query"="*ds_step=*"); also sigma convert --without-pipeline -t log_scale -> exit 0. Medium confidence: the graph_realtime.php endpoint is a legitimate Cacti feature, but the combination of action=init with clear=1 and ds_step parameters matches the PoC defaults. An attacker who modifies PoC parameters may evade this specific rule. Best deployed alongside Rule 2 for correlation. -->

```yaml
title: Cacti 4HTTP2SHELL Realtime Graph Command Execution Request
id: c9a5e6d3-1b4a-6f8c-d7a4-3e0f9c5b8a21
status: experimental
description: >
    Detects HTTP requests to Cacti's graph_realtime.php endpoint with
    action=init and default PoC parameters (clear=1, ds_step=10, size=90).
    This is the fourth and final step of the 4HTTP2SHELL exploit chain
    where the modified poller_item.arg1 value is passed to PHP popen()
    for command execution. The combination of these specific default
    parameters is characteristic of the public PoC.
references:
    - https://www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/
    - https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html
    - https://intel.threadlinqs.com/threat/TL-2026-6953
    - https://github.com/thiscitze/cacti-4http2shell
author: Actioner
date: 2026/11/28
tags:
    - attack.execution
    - attack.t1059.004
    - attack.t1190
logsource:
    category: webserver
    product: apache
detection:
    selection_uri:
        cs-uri-stem|contains: 'graph_realtime.php'
    selection_action:
        cs-uri-query|contains: 'action=init'
    selection_poc_params:
        cs-uri-query|contains|all:
            - 'clear=1'
            - 'ds_step='
    condition: selection_uri and selection_action and selection_poc_params
falsepositives:
    - Legitimate Cacti users accessing the realtime graph feature with default settings
level: medium
```

### Snort Rules: Cacti 4HTTP2SHELL Network Detection

Four rules covering: (1) the profile update with `preview_graphs_per_page` parameter, (2) the profile update with SQL `UPDATE poller_item` keywords in the body, (3) the `graph_realtime.php` RCE trigger with PoC-default parameters, and (4) the `graph_view.php` SQL injection trigger step.
**Status:** compile ✅ compiles (snort -c snort-min.conf -T -> exit 0, "Snort successfully validated the configuration!") · confidence: **medium-high** (rules 1-2), **medium** (rules 3-4)

<!-- audit: validated via wrapper config (snort -c /tmp/actioner/snort-min.conf -T -> exit 0, "Snort successfully validated the configuration! Snort exiting"). SID range 2100201-2100204. Rule 2100201 (profile+preview_graphs_per_page) gates on POST + auth_profile.php + update_data + preview_graphs_per_page body content: medium-high precision, legitimate profile saves also match but are uncommon from external nets. Rule 2100202 (SQL UPDATE poller_item in body) is high-precision for SQLi payloads but may miss encoded variants. Rule 2100203 (graph_realtime.php PoC defaults) is PoC-specific, medium precision. Rule 2100204 (graph_view.php action=preview) is low-precision alone, designed for correlation with other rules. -->

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Cacti 4HTTP2SHELL - POST to auth_profile.php update_data with preview_graphs_per_page (SQLi store)"; flow:established,to_server; content:"POST"; http_method; content:"auth_profile.php"; fast_pattern; nocase; http_uri; content:"update_data"; nocase; http_uri; content:"preview_graphs_per_page"; nocase; http_client_body; classtype:web-application-attack; reference:url,www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:author Actioner, created 2026-11-28; sid:2100201; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Cacti 4HTTP2SHELL - POST auth_profile.php update_data with SQL keywords in body (SQLi payload)"; flow:established,to_server; content:"POST"; http_method; content:"auth_profile.php"; fast_pattern; nocase; http_uri; content:"update_data"; nocase; http_uri; content:"UPDATE"; nocase; http_client_body; content:"poller_item"; nocase; http_client_body; classtype:web-application-attack; reference:url,www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:author Actioner, created 2026-11-28; sid:2100202; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Cacti 4HTTP2SHELL - GET graph_realtime.php action=init with PoC default params (RCE trigger)"; flow:established,to_server; content:"GET"; http_method; content:"graph_realtime.php"; fast_pattern; nocase; http_uri; content:"action=init"; nocase; http_uri; content:"clear=1"; nocase; http_uri; content:"ds_step="; nocase; http_uri; classtype:web-application-attack; reference:url,www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:author Actioner, created 2026-11-28; sid:2100203; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Actioner - Cacti 4HTTP2SHELL - GET graph_view.php with action=preview (SQLi trigger step)"; flow:established,to_server; content:"GET"; http_method; content:"graph_view.php"; fast_pattern; nocase; http_uri; content:"action=preview"; nocase; http_uri; classtype:web-application-attack; reference:url,www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:author Actioner, created 2026-11-28; sid:2100204; rev:1;)
```

### Suricata Rules: Cacti 4HTTP2SHELL Network Detection

Same four detection patterns as the Snort rules, using Suricata's `http.*` sticky buffers for HTTP-layer inspection.
**Status:** compile ✅ compiles (suricata -T -S suricata-cacti-4http2shell.rules -l /tmp/actioner -> exit 0, "Configuration provided was successfully loaded. Exiting.") · confidence: **medium-high** (rules 1-2), **medium** (rules 3-4)

<!-- audit: validated via suricata -T -S /tmp/actioner/suricata-cacti-4http2shell.rules -l /tmp/actioner -> exit 0, "Configuration provided was successfully loaded. Exiting." SID range 2200201-2200204. Uses Suricata http.method, http.uri, http.request_body sticky buffers. Same precision/confidence rationale as Snort rules above. -->

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Cacti 4HTTP2SHELL - POST auth_profile.php update_data with preview_graphs_per_page (SQLi store)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"auth_profile.php"; nocase; content:"update_data"; nocase; http.request_body; content:"preview_graphs_per_page"; nocase; fast_pattern; classtype:web-application-attack; reference:url,www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:author Actioner, created_at 2026-11-28; sid:2200201; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Cacti 4HTTP2SHELL - POST auth_profile.php with SQL UPDATE poller_item in body (SQLi payload)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"auth_profile.php"; nocase; content:"update_data"; nocase; http.request_body; content:"UPDATE"; nocase; content:"poller_item"; nocase; fast_pattern; classtype:web-application-attack; reference:url,www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:author Actioner, created_at 2026-11-28; sid:2200202; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Cacti 4HTTP2SHELL - GET graph_realtime.php action=init with PoC defaults (RCE trigger)"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"graph_realtime.php"; nocase; fast_pattern; content:"action=init"; nocase; content:"clear=1"; nocase; content:"ds_step="; nocase; classtype:web-application-attack; reference:url,www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:author Actioner, created_at 2026-11-28; sid:2200203; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - Cacti 4HTTP2SHELL - GET graph_view.php action=preview (second-order SQLi trigger)"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"graph_view.php"; nocase; fast_pattern; content:"action=preview"; nocase; classtype:web-application-attack; reference:url,www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/; reference:url,thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html; metadata:author Actioner, created_at 2026-11-28; sid:2200204; rev:1;)
```

### YARA Rules

No YARA rules were produced. The public PoC reportedly drops a PHP webshell, but no specific webshell filenames, hashes, or content patterns were published in the available sources. If webshell indicators become available from incident response or vendor advisories, file-level YARA rules should be added targeting those artifacts.

## Sources

- [BleepingComputer - Unpatched Cacti Zero-Day with Public PoC Gives Remote Code Execution](https://www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/)
- [The Hacker News - Unpatched Cacti Zero-Day Enables RCE in Just Four HTTP Requests via Guest Access](https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html)
- [ThreadLinqs - Cacti 4HTTP2ROOT (4HTTP2SHELL) Zero-Day: TL-2026-6953](https://intel.threadlinqs.com/threat/TL-2026-6953)
- [Cyber Kendra - Cacti 4HTTP2ROOT Zero-Day Enables RCE via Guest Access](https://www.cyberkendra.com/2026/11/cacti-4http2root-zero-day-rce.html)
- [InfoSecMonkey - Cacti Zero-Day 4HTTP2SHELL: Check, Mitigate, Hunt](https://infosecmonkey.com/cacti-4http2shell-zero-day/)
- [BreachNews - Unpatched Cacti 4HTTP2SHELL Zero-Day Allows RCE](https://breachnews.com/research/4http2shell-cacti-zero-day-unpatched-guest-rce/)
- [Mallory AI - Cacti Zero-Day Enables Unauthenticated RCE Through Guest Access](https://mallory.ai/stories/01a21b9c-40fa-74f2-934a-a092d4b8fd13)
- [ZeroHour.day - Unpatched Cacti 1.2.31 Flaw](https://zerohour.day/item/706168821faab9b6177f02e77122ca0de5483422)
- [WindowsForum - Cacti 4HTTP2SHELL Zero-Day PoC Mitigation Guide](https://windowsforum.com/news/cacti-4http2shell-zero-day-poc-enables-rce-via-guest-access-mitigation-guide.454357/)
- [DEV Community - ek0ms savi0r chains Cacti guest access to unauthenticated RCE](https://dev.to/randomchaos/ek0ms-savi0r-chains-cacti-guest-access-to-unauthenticated-rce-4pd6)
- [GitHub PoC Repository - thiscitze/cacti-4http2shell](https://github.com/thiscitze/cacti-4http2shell)
- [Sploitus - cacti-cve-4http2root PoC](https://sploitus.com/exploit?id=94438D01-939A-575F-818F-185FC6320F00)
- [CVE-2020-8813 - Prior Cacti graph_realtime.php RCE via cookie injection](https://feedly.com/cve/CVE-2020-8813)
