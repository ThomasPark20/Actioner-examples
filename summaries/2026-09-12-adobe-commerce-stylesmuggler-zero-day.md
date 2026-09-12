# Technical Analysis Report: StyleSmuggler — Adobe Commerce / Magento Zero-Day (CVE-2026-75650)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-12
Version: 1.0 (DRAFT)

## Executive Summary

CVE-2026-75650, dubbed "StyleSmuggler," is a CVSS 10.0 unauthenticated remote code execution zero-day in Adobe Commerce (2.4.4–2.4.9), Magento Open Source (2.4.4–2.4.9), and Adobe Commerce B2B (1.3.3–1.5.3). Discovered by Dutch e-commerce security firm Sansec, exploitation began on September 4, 2026 — three days before Adobe released a patch (APSB26-146) on September 7. CISA added it to the Known Exploited Vulnerabilities catalog on September 8 with a federal remediation deadline of September 11. The attack chain abuses Magento's template-processing and dependency-injection system to achieve code execution without authentication, deploying a Rust-based Linux backdoor and a PHP web shell/dropper. At least 26 distinct source addresses using residential proxies have been observed exploiting this flaw in the wild. All Adobe Commerce and Magento stores running versions through the August 2026 release are vulnerable unless the VULN-39341 hotfix is applied.

## Background: Adobe Commerce / Magento Open Source

Adobe Commerce (formerly Magento Commerce) and Magento Open Source power an estimated 250,000+ online stores globally. The platform's template engine, dependency-injection compiler, and email rendering pipeline are deeply intertwined — a design that StyleSmuggler turns into an attack surface. Because Magento stores process payment card data, any RCE vulnerability presents immediate PCI-DSS compliance and financial fraud risk. The platform has been a recurring target: CosmicSting (CVE-2024-34102) exploited a similar template injection path in 2024, and this is the second critical Commerce zero-day in 2026 (following CVE-2026-71362, an authentication bypass patched in August).

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-09-04 22:20 | First confirmed exploitation in Sansec telemetry |
| 2026-09-04 23:10 | Disrex confirms compromise of managed Magento server (~50 min after first exploitation) |
| 2026-09-05 | Sansec publishes advisory; defensive rules deployed; Disrex/ProxiBlue release unofficial patches |
| 2026-09-06 | Adobe has not yet published CVE, patch, or workaround; attacker deploys fc-cache variant (v2.1.4) |
| 2026-09-07 | Attacker deploys chronyd variant (v2.1.5); Adobe publishes APSB26-146 at 20:20 UTC |
| 2026-09-07 onward | Previdian honeypots record 12 exploitation attempts from 2 IPs (Chinese, Romanian) |
| 2026-09-08 | CISA adds CVE-2026-75650 to KEV catalog; federal deadline set to September 11 |

## Root Cause: Template Injection via Dependency-Injection Compiler

StyleSmuggler exploits a two-stage chain in Magento's core template processing:

1. **Injection stage**: The attacker sends a crafted POST request to the `/graphql` endpoint (or `/paypal/transparent/response/`) with a `styles[...]` parameter containing malicious PHP code. This code is written into files Magento naturally creates — specifically failure reports in `var/report/` or log entries in `var/log/system.log`. The `styles` property bypasses existing input sanitization because template-style attributes were not subject to the same restrictions as other template directives.

2. **Execution stage**: Magento's dependency-injection compiler (`setup/src/Magento/Setup/Module/Di/Code/`) processes these poisoned files. The rendering of a "Payment Transaction Failed Reminder" email triggers inclusion of attacker-controlled file paths from the poisoned logs, achieving code execution without requiring the email to actually be delivered or any user interaction.

The technical sink is the DI compiler's file-scanning code path, which trusts the contents of log and report files as legitimate PHP class references to compile. This is an unauthenticated attack — no credentials, session, or admin access are required.

## Technical Analysis of the Malicious Payload

### 1. Initial Exploitation — GraphQL Template Injection

The exploitation request takes the form:

```
POST /graphql?styles[...]=<PHP_PAYLOAD>
Store: <header containing injected PHP code>
Body: {"query":"query { storeConfig { store_code } }"}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

An alternative vector uses the PayPal transparent response endpoint:
```
POST /paypal/transparent/response/?<?=eval(base64_decode('...
```

**Early-warning indicator (Disrex)**: Malformed "Payment Transaction Failed Reminder" emails containing unresolved template variables (`{{var ...}}` tags), `.invalid` domain addresses, and zero totals signal successful exploitation.

**Log signature**: A `TypeError` from `array_merge()` appears in `system.log` immediately post-exploit, though stealthier variants return an empty array and leave no trace.

### 2. PHP Dropper / Web Shell

Upon achieving RCE, the attacker deploys a PHP dropper (SHA-256: `d61217ca0bca83204302fa7b41935ce36f73764559c156d5c980f2fedddffb6e`). The dropper:

- Attempts six PHP functions sequentially to spawn a process: `proc_open()`, `shell_exec()`, `passthru()`, `system()`, `popen()`, `exec()`
- Downloads the Rust backdoor binary from `hxxps://247[.]cdnflare[.]xyz` (or from a compromised Italian website: `hxxps://www[.]incofar[.]it/js/jquery/plugins/ajaxfileupload/mag.txt`)
- Writes a persistent web shell to: `pub/media/catalog/product/cache/ss_<10hex>/sync_<10hex>.php`

The web shell uses a custom authentication mechanism:
- Requires the HTTP header `X-Cache-Token: fced27f6d57702565353ecc11722533b`
- Accepts PHP code execution via a `task` POST parameter
- Campaign markers: `ss5_457cfa2fb7`, `ss6_457cfa2fb7_`

### 3. Rust-Based Linux Backdoor

The primary implant is a statically-linked Rust binary (~1.9 MB), compiled for x86-64 and arm64. Three variants have been observed:

| Variant | Process Name | Version | First Seen | SHA-256 |
|---------|-------------|---------|------------|---------|
| Initial | `[kworker/u:8:0]` | — | Sep 4 | `e315687a...a26a7` |
| fc-cache | `fc-cache` | 2.1.4 | Sep 6 | `4352caba...ae8e` |
| chronyd | `chronyd` | 2.1.5 | Sep 7 | `1a3374ff...75d` |

**Execution and persistence**:
- Runs as the unprivileged web application user (not root)
- Writes directly to the cron spool file (bypasses `crontab` command logging)
- Re-adds its cron entry within 1 second if removed
- Cron patterns: `*/5 * * * *` (gvfsd variant), `13,43 * * * *` (fc-cache), `57,27 * * * *` (chronyd)

**Process masquerading**: The implant renames its process to mimic legitimate Linux system processes. The `[kworker/u:8:0]` name imitates a kernel worker thread, but can be distinguished because it runs as a non-root user with resident memory (genuine kworker threads are kernel-only).

### 4. C2 Infrastructure

**NTP-shaped UDP beaconing (port 123)**:
The Rust backdoor disguises C2 traffic as NTP (Network Time Protocol) by emitting nine 48-byte NTPv4 server-mode datagrams approximately 10 ms apart, every 60 seconds. The beacon reports: agent ID, hostname, username, OS version, memory/disk usage, uptime, root privileges, and implant version.

C2 domains use typosquatted names mimicking legitimate NTP and Microsoft services:

| Domain | Purpose |
|--------|---------|
| `ntp[.]timesync[.]to` | C2 beacon (fc-cache build) |
| `ntp[.]timesysnc[.]net` | C2 beacon (note: "sysnc" typo) |
| `time[.]microsft[.]run` | C2 beacon (note: "microsft" typo) |
| `pool[.]microsft[.]studio` | C2 beacon |
| `ntp[.]synctime[.]to` | C2 fallback |
| `ntp[.]syncstime[.]to` | C2 fallback |

All NTP C2 domains resolved to `185[.]157[.]160[.]251` on September 7.

**WebSocket/TLS (port 443)**:
- `99[.]84[.]67[.]186:443` — WebSocket over TLS for interactive command relay
- `windwsecurity[.]run:443` — remote shell access

**Exfiltration**: `checkout-cdn[.]com` (designed to blend in with e-commerce CDN traffic)

**Reconnaissance**: DNS callback via `*.daf892t5qau4og8pi4cghbc6fhm1dim3u[.]oast[.]site`; IP detection via `api4[.]ipify[.]org`, `ipv4[.]icanhazip[.]com`, `ipv4[.]ident[.]me`, `ipinfo[.]io`

### 5. Anti-Forensics / Evasion Techniques

- **Process name spoofing**: Masquerades as kernel threads (`kworker`) or system daemons (`fc-cache`, `chronyd`)
- **Direct cron spool manipulation**: Writes persistence entries directly to the spool file rather than using `crontab`, avoiding audit log entries
- **NTP traffic mimicry**: C2 traffic uses UDP port 123 with valid-looking NTP packet structure
- **Rapid re-persistence**: Cron entry is re-added within 1 second of removal
- **Stealthy error handling**: Later exploit variants return empty arrays instead of triggering `TypeError` log entries
- **Legitimate-looking infrastructure**: C2 domains typosquat Microsoft and NTP pool names; exfil domain mimics e-commerce CDN
- **Web shell auth gate**: The PHP web shell requires a specific `X-Cache-Token` value, preventing discovery via casual browsing

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File System

| Platform | Path | Hash (SHA-256) | Description |
|----------|------|---------------|-------------|
| Linux | `~/.local/share/.gvfsd/gvfsd-user` | `e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7` | Rust backdoor (initial variant) |
| Linux | `~/.local/share/.gvfsd/gvfsd-user` | `8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef` | Rust backdoor (on-disk variant) |
| Linux | (memory dump) | `251fabd50d7b18a8b5e1b3ef5d64e7198c17244778f6461fb1ab07f6169bf220` | Rust backdoor (memory variant) |
| Linux | `~/.local/share/.gvfsd/.gvfsd_<8hex>.lock` | — | PID lock file |
| Linux | `~/.cache/fontconfig/fc-cache` | `4352cabaa451e5a894535fbcc4d46628701303322a13745cb5479d7d0534ae8e` | Rust backdoor (fc-cache variant, x64, 2,270,031 bytes) |
| Linux | `~/.cache/fontconfig/fc-cache` | `d2fbf9eb75c495bfea48790d3b228fab0c15a282419c3d3f5e49294c4e1a3e82` | Rust backdoor (fc-cache variant, arm64) |
| Linux | `/tmp/.chrony-<8hex>/chronyd` | `1a3374ffac5b0a62467612f264c49792d206304d4514409c982325c91231375d` | Rust backdoor (chronyd variant) |
| Linux | `/tmp/.kw_<random><random>` | — | Temporary execution file |
| Linux | `/tmp/.cache_<random><random>` | — | Temporary execution file |
| Linux | `/tmp/.fc-<8hex>/fc-cache` | — | Temporary staging |
| Linux | `/tmp/.fc_<8hex>.lock` | — | PID file |
| Linux | `pub/media/catalog/product/cache/ss_<10hex>/sync_<10hex>.php` | — | PHP web shell |
| Linux | (dropper) | `d61217ca0bca83204302fa7b41935ce36f73764559c156d5c980f2fedddffb6e` | PHP dropper |
| Linux | `var/report/` | — | Injection point (failure reports) |
| Linux | `var/log/system.log` | — | Injection point (log poisoning) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `247[.]cdnflare[.]xyz` | Malware download |
| Domain | `windwsecurity[.]run` | Remote shell C2 |
| Domain | `ntp[.]timesync[.]to` | NTP-shaped C2 beacon |
| Domain | `ntp[.]timesysnc[.]net` | NTP-shaped C2 beacon |
| Domain | `time[.]microsft[.]run` | NTP-shaped C2 beacon |
| Domain | `pool[.]microsft[.]studio` | NTP-shaped C2 beacon |
| Domain | `ntp[.]synctime[.]to` | NTP-shaped C2 fallback |
| Domain | `ntp[.]syncstime[.]to` | NTP-shaped C2 fallback |
| Domain | `checkout-cdn[.]com` | Data exfiltration |
| Domain | `*[.]daf892t5qau4og8pi4cghbc6fhm1dim3u[.]oast[.]site` | Reconnaissance callback |
| IP | `185[.]157[.]160[.]251` | NTP C2 server (A record) |
| IP | `99[.]84[.]67[.]186:443` | WebSocket/TLS C2 |
| IP | `209[.]141[.]43[.]95` | Malware hosting |
| IP | `88[.]216[.]72[.]181` | Attacker source |
| IP | `88[.]216[.]72[.]182` | Attacker source |
| IP | `182[.]182[.]152[.]48` | Attacker source |
| IP | `76[.]31[.]99[.]207` | Attacker source |
| IP | `209[.]73[.]130[.]148` | Attacker source |
| IP | `77[.]239[.]124[.]107` | Attacker source |
| IP | `98[.]224[.]189[.]28` | Attacker source |
| URL | `hxxps://www[.]incofar[.]it/js/jquery/plugins/ajaxfileupload/mag.txt` | Secondary malware download |
| URL Pattern | `POST /graphql?styles[...]=` | Exploitation request |
| URL Pattern | `POST /paypal/transparent/response/?<?=eval(` | Alternative exploitation request |

### Behavioral

- Processes named `[kworker/u:8:0]`, `fc-cache`, or `chronyd` running as a non-root web application user
- Nine 48-byte NTPv4 server-mode UDP datagrams emitted ~10 ms apart on port 123 every 60 seconds
- Cron entries with `exec <home>/.local/share/.gvfsd/gvfsd-user` or pointing to `~/.cache/fontconfig/fc-cache` or `/tmp/.chrony-*/chronyd`
- Cron entries written directly to spool file (bypassing `crontab` command)
- `TypeError` from `array_merge()` in Magento `system.log`
- Malformed "Payment Transaction Failed Reminder" emails with `{{var ...}}` template tags, `.invalid` domain addresses, and $0.00 totals
- Truncated User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` (missing browser engine trailer)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Unauthenticated RCE via Magento GraphQL/PayPal endpoint template injection |
| T1059.004 | Unix Shell | PHP dropper spawns shell via `proc_open()` and five fallback execution functions |
| T1505.003 | Web Shell | PHP web shell deployed to `pub/media/catalog/product/cache/` with token-based authentication |
| T1036.004 | Masquerade Task or Service | Rust backdoor masquerades as `kworker`, `fc-cache`, or `chronyd` system processes |
| T1053.003 | Cron | Persistence via direct cron spool file manipulation; re-adds within 1 second of removal |
| T1071.001 | Application Layer Protocol: Web Protocols | WebSocket/TLS C2 on port 443 |
| T1071.004 | Application Layer Protocol: DNS | Reconnaissance data exfiltrated via DNS callbacks to `oast.site` |
| T1001.003 | Data Obfuscation: Protocol Impersonation | C2 traffic disguised as NTP (UDP port 123) with valid packet structure |
| T1105 | Ingress Tool Transfer | Rust binary downloaded from `247[.]cdnflare[.]xyz` via PHP dropper |
| T1082 | System Information Discovery | Beacon reports hostname, username, OS version, memory, disk, uptime |
| T1016 | System Network Configuration Discovery | IP address enumeration via `ipify.org`, `icanhazip.com`, `ident.me`, `ipinfo.io` |
| T1041 | Exfiltration Over C2 Channel | Payment/store data exfiltrated to `checkout-cdn[.]com` |

## Impact Assessment

**Breadth**: All Adobe Commerce and Magento Open Source installations running versions 2.4.4 through 2.4.9 (including fully-patched August 2026 releases) are vulnerable. This encompasses an estimated 250,000+ active stores. At least 26 distinct attacker source addresses have been observed, and the vulnerability was actively exploited for 3 days before a patch existed.

**Depth**: As an unauthenticated RCE with CVSS 10.0, exploitation grants full control over the web application layer. The Rust backdoor provides persistent access with C2 capability. Given that Magento stores process payment card data, compromise implies potential PCI-DSS scope impact and financial fraud risk.

**Stealth**: The implant uses sophisticated evasion — NTP-shaped C2 traffic, process name spoofing, direct cron spool manipulation, and later variants suppressed log evidence. The web shell requires a specific authentication token, preventing casual discovery. Rapid attacker iteration (three backdoor variants in four days) demonstrates active development.

## Detection & Remediation

### Immediate Detection

Run the following on all Magento/Adobe Commerce servers:

```bash
# Check for backdoor files
ls -la ~/.local/share/.gvfsd/ ~/.cache/fontconfig/fc-cache /tmp/.kw_* /tmp/.cache_* /tmp/.gvfsd-* /tmp/.fc-*/fc-cache /tmp/fc-cache /tmp/.chrony-*/chronyd 2>/dev/null

# Check for suspicious cron entries
crontab -l | grep -iE 'gvfsd|fc-cache|chronyd'

# Check for masquerading processes
ps -eo pid,user,comm,args | grep -iE 'kworker|fc-cache|chronyd' | grep -v '^\s*root'

# Check for PHP files in media directories (should never exist)
find pub/media -name '*.php' -ls

# Check for injection markers in error reports
grep -ril 'x_trace_' var/report/ 2>/dev/null

# Check for recently modified PHP files since exploitation began
find ./pub ./generated -name '*.php' -newermt '2026-09-04' -ls

# Check outbound connections to known C2
ss -tunp | grep -E '185\.157\.160\.251|99\.84\.67\.186|209\.141\.43\.95'
```

### Remediation

1. **Apply patch VULN-39341 immediately** — download from `repo.magento.com` and apply as a Composer patch
2. **Rotate all encryption keys** — this is mandatory, not optional, as the attacker may have extracted existing keys
3. **Hunt for IOCs** — run the detection commands above; check for unauthorized cron entries and suspicious processes
4. **Remove any PHP files found in `pub/media/`** — these are web shells; legitimate media directories never contain PHP files
5. **Kill suspicious processes** and remove cron entries, noting that the implant will re-add cron within 1 second (remove binary first)
6. **Block C2 infrastructure** at the network perimeter — add all listed domains and IPs to blocklists
7. **Review access logs** for POST requests to `/graphql` with `styles[` parameters or to `/paypal/transparent/response/` with eval payloads
8. **Assess PCI-DSS exposure** — if the store was compromised, initiate incident response per PCI requirements

### Long-Term Hardening

- **Disable `proc_open()`** in PHP `disable_functions` (reduces dropper's execution options)
- **Mount `/tmp`, `/var/tmp`, `/dev/shm` with `noexec`** — prevents execution of dropped binaries from temp directories
- **File integrity monitoring** on `pub/media/`, `var/report/`, and cron spool directories
- **Network monitoring** for anomalous NTP traffic (UDP port 123) from non-NTP hosts, and for outbound WebSocket connections from web servers
- **WAF rules** to block `styles[` parameters in GraphQL requests and eval payloads in PayPal endpoints

## Detection Rules

Three Sigma rules, two YARA rules, and Suricata/Snort network rules provide layered detection across web server logs, file system events, and network traffic. The YARA rules target the Rust backdoor (ELF binary with C2 domain strings and process masquerade names) and the PHP dropper/web shell (authentication token and campaign markers). Note: the C2's NTP-shaped UDP traffic may not be inspected by default in HTTP-focused IDS deployments — ensure UDP port 123 is monitored for non-NTP hosts.

### Sigma: StyleSmuggler GraphQL/PayPal Exploitation (Web Server Logs)

compile: passed (sigma convert) | confidence: high

```yaml
title: StyleSmuggler CVE-2026-75650 Magento Exploitation via GraphQL Template Injection
id: b4e7c1a9-3d6f-4e82-9a5b-8c1d0e7f2a3b
status: experimental
description: >
    Detects HTTP requests indicative of CVE-2026-75650 (StyleSmuggler) exploitation
    against Adobe Commerce / Magento Open Source. The attack uses POST requests to
    the /graphql endpoint with styles parameters containing PHP code injection,
    or to the /paypal/transparent/response/ endpoint with embedded PHP eval payloads.
references:
    - https://sansec.io/research/stylesmuggler-0day
    - https://thehackernews.com/2026/09/adobe-patches-magento-zero-day.html
author: Actioner
date: 2026-09-12
tags:
    - attack.t1190
    - attack.t1059.004
logsource:
    category: webserver
detection:
    selection_graphql_styles:
        cs-uri-stem|contains: '/graphql'
        cs-uri-query|contains: 'styles['
        cs-method: 'POST'
    selection_paypal_eval:
        cs-uri-stem|contains: '/paypal/transparent/response/'
        cs-uri-query|contains:
            - 'eval(base64_decode'
            - 'eval(gzinflate'
    condition: selection_graphql_styles or selection_paypal_eval
falsepositives:
    - Legitimate Magento GraphQL requests do not include styles[] parameters in the query string
level: critical
```

<!-- audit: Validated via sigma convert --without-pipeline -t splunk (exit 0). sigma check fails due to network error fetching MITRE ATT&CK data (proxy 403), not a rule syntax issue. Detection targets the two known exploit URI patterns from Sansec research. POST-body variant of styles[] injection (without query-string reflection) would evade this rule — requires full-body inspection at WAF/proxy layer. Fields cs-uri-stem, cs-uri-query, cs-method map to standard web server log fields (IIS/Apache/Nginx). -->

### Sigma: PHP Web Shell in Magento Media Directory

compile: passed (sigma convert) | confidence: high

```yaml
title: StyleSmuggler PHP Web Shell Created in Magento Media Directory
id: c5f8d2ba-4e7a-5f93-ab6c-9d2e1f8a3b4c
status: experimental
description: >
    Detects creation of PHP files in the Magento pub/media/catalog/product/cache/
    directory matching the StyleSmuggler web shell naming convention
    (ss_<hex>/sync_<hex>.php). PHP files should never appear in media cache directories.
references:
    - https://sansec.io/research/stylesmuggler-0day
    - https://thehackernews.com/2026/09/adobe-patches-magento-zero-day.html
author: Actioner
date: 2026-09-12
tags:
    - attack.t1505.003
logsource:
    category: file_event
    product: linux
detection:
    selection_path:
        TargetFilename|contains: 'pub/media/catalog/product/cache/ss_'
        TargetFilename|endswith: '.php'
    selection_media_php:
        TargetFilename|contains: 'pub/media/'
        TargetFilename|endswith: '.php'
    condition: selection_path or selection_media_php
falsepositives:
    - Custom Magento modules that intentionally place PHP files in media directories (very rare)
level: critical
```

<!-- audit: Validated via sigma convert --without-pipeline -t splunk (exit 0). UUID fixed from invalid hex 'g' to 'a'. selection_path is highly specific to the ss_<hex>/sync_<hex>.php pattern; selection_media_php is a broader catch-all since PHP files in pub/media/ are almost always malicious. Requires file_event logging (auditd, inotify, or EDR on Linux). -->

### Sigma: Rust Backdoor File Creation / Process Masquerading

compile: passed (sigma convert) | confidence: high

```yaml
title: StyleSmuggler Rust Backdoor File Creation or Process Execution
id: d6a9e3cb-5f8a-6a04-bc7d-ae3f2a9b4c5d
status: experimental
description: >
    Detects file creation or process execution patterns associated with the
    StyleSmuggler Rust-based backdoor. The implant masquerades as legitimate
    system processes (kworker, fc-cache, chronyd) and drops files in hidden
    directories under the user's home or /tmp.
references:
    - https://sansec.io/research/stylesmuggler-0day
    - https://thehackernews.com/2026/09/unpatched-magento-and-adobe-commerce.html
author: Actioner
date: 2026-09-12
tags:
    - attack.t1036.004
    - attack.t1053.003
logsource:
    category: file_event
    product: linux
detection:
    selection_gvfsd:
        TargetFilename|contains: '.local/share/.gvfsd/gvfsd-user'
    selection_fc_cache_hidden:
        TargetFilename|contains: '.cache/fontconfig/fc-cache'
    selection_tmp_patterns:
        TargetFilename|re: '/tmp/\.(kw_|cache_|fc-|fc_|chrony-|gvfsd)'
    condition: 1 of selection*
falsepositives:
    - Legitimate GNOME gvfsd processes (verify the binary is from a system package)
    - System fontconfig cache updates (fc-cache in standard paths, not hidden directories)
level: high
```

<!-- audit: Validated via sigma convert --without-pipeline -t splunk (exit 0). UUID fixed from invalid hex 'h' to 'a'. The regex in selection_tmp_patterns targets the /tmp/.<prefix> naming convention across all three known variants. False positives: genuine gvfsd-user binary exists on GNOME desktops but lives in /usr/libexec/; genuine fc-cache lives in /usr/bin/; neither should appear in hidden dotfile directories. -->

### YARA: StyleSmuggler Rust Backdoor Binary

compile: passed (yarac exit 0) | confidence: high

```yara
rule Malware_StyleSmuggler_Rust_Backdoor
{
    meta:
        description = "Detects the StyleSmuggler Rust-based Linux backdoor deployed via CVE-2026-75650 exploitation of Adobe Commerce / Magento. Matches known sample hashes and behavioral strings."
        author = "Actioner"
        date = "2026-09-12"
        reference = "https://sansec.io/research/stylesmuggler-0day"
        hash = "e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7"
        hash = "4352cabaa451e5a894535fbcc4d46628701303322a13745cb5479d7d0534ae8e"
        hash = "1a3374ffac5b0a62467612f264c49792d206304d4514409c982325c91231375d"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $proc1 = "[kworker/u:8:0]" ascii
        $proc2 = "fc-cache" ascii fullword
        $proc3 = "chronyd" ascii fullword
        $c2_1 = "windwsecurity.run" ascii
        $c2_2 = "ntp.timesync.to" ascii
        $c2_3 = "ntp.timesysnc.net" ascii
        $c2_4 = "time.microsft.run" ascii
        $c2_5 = "pool.microsft.studio" ascii
        $c2_6 = "ntp.synctime.to" ascii
        $c2_7 = "ntp.syncstime.to" ascii
        $path1 = ".local/share/.gvfsd/gvfsd-user" ascii
        $path2 = ".cache/fontconfig/fc-cache" ascii
        $path3 = ".gvfsd_" ascii
        $path4 = ".fc_" ascii
        $camp1 = "ss5_457cfa2fb7" ascii
        $camp2 = "ss6_457cfa2fb7" ascii
        $dl1 = "247.cdnflare.xyz" ascii
        $dl2 = "incofar.it" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            2 of ($c2_*) or
            1 of ($camp*) or
            (1 of ($proc*) and 1 of ($path*)) or
            (1 of ($c2_*) and 1 of ($path*)) or
            1 of ($dl*)
        )
}
```

<!-- audit: Compiled cleanly with yarac (exit 0). ELF magic header check (0x464C457F) restricts to Linux binaries. Size cap 5MB accommodates the ~1.9MB observed samples with margin. The C2 domains are highly distinctive (typosquats of Microsoft/NTP names); requiring 2-of-7 reduces FP risk while catching variants that rotate subsets. Campaign markers ss5_/ss6_ are unique identifiers from this operation. The $dl* strings (cdnflare.xyz, incofar.it) are highly specific hosting infrastructure. -->

### YARA: StyleSmuggler PHP Dropper / Web Shell

compile: passed (yarac exit 0) | confidence: high

```yara
rule Malware_StyleSmuggler_PHP_Dropper_WebShell
{
    meta:
        description = "Detects the StyleSmuggler PHP dropper / web shell component deployed via CVE-2026-75650. The web shell requires an X-Cache-Token header and accepts PHP code via a task POST parameter."
        author = "Actioner"
        date = "2026-09-12"
        reference = "https://sansec.io/research/stylesmuggler-0day"
        hash = "d61217ca0bca83204302fa7b41935ce36f73764559c156d5c980f2fedddffb6e"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $auth1 = "X-Cache-Token" ascii nocase
        $auth2 = "fced27f6d57702565353ecc11722533b" ascii
        $exec1 = "proc_open" ascii
        $exec2 = "shell_exec" ascii
        $exec3 = "passthru" ascii
        $exec4 = "system(" ascii
        $exec5 = "popen(" ascii
        $exec6 = "exec(" ascii
        $dl1 = "247.cdnflare.xyz" ascii
        $dl2 = "cdnflare" ascii
        $tmpl1 = "x_trace_" ascii
        $tmpl2 = "var/report/" ascii
        $tmpl3 = "setup/src/Magento/Setup/Module/Di" ascii
        $camp1 = "ss5_457cfa2fb7" ascii
        $camp2 = "ss6_457cfa2fb7_" ascii
        $recon1 = "oast.site" ascii
        $recon2 = "ipify.org" ascii
        $recon3 = "icanhazip.com" ascii

    condition:
        filesize < 100KB and
        (
            ($auth1 and $auth2) or
            ($auth1 and 2 of ($exec*) and 1 of ($dl*)) or
            1 of ($camp*) or
            (2 of ($exec*) and 1 of ($dl*) and 1 of ($tmpl*)) or
            ($auth2 and 1 of ($exec*)) or
            (1 of ($dl*) and 1 of ($recon*) and 1 of ($exec*))
        )
}
```

<!-- audit: Compiled cleanly with yarac (exit 0) after adding $recon* to condition (initially unreferenced). The auth token MD5 fced27f6d57702565353ecc11722533b is the primary high-confidence indicator — unique to this campaign. The campaign markers are equally specific. The exec function strings are common in PHP files, so they're always gated behind at least one campaign-specific indicator. Size cap 100KB fits the 485-byte dropper and small web shell. -->

### Suricata: StyleSmuggler C2 and Exploitation (9 rules)

compile: not validated (suricata binary not available) | confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - StyleSmuggler C2 DNS Query to NTP Typosquat Domain (timesync.to)"; flow:to_server; dns.query; content:"ntp.timesync.to"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-12; sid:2026750001; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - StyleSmuggler C2 DNS Query to NTP Typosquat Domain (timesysnc.net)"; flow:to_server; dns.query; content:"ntp.timesysnc.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-12; sid:2026750002; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - StyleSmuggler C2 DNS Query to Typosquat Domain (microsft.run)"; flow:to_server; dns.query; content:"microsft.run"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-12; sid:2026750003; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - StyleSmuggler C2 DNS Query to Typosquat Domain (microsft.studio)"; flow:to_server; dns.query; content:"microsft.studio"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-12; sid:2026750004; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - StyleSmuggler C2 DNS Query to windwsecurity.run"; flow:to_server; dns.query; content:"windwsecurity.run"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-12; sid:2026750005; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - StyleSmuggler Malware Download Domain (cdnflare.xyz)"; flow:to_server; dns.query; content:"cdnflare.xyz"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-12; sid:2026750006; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - StyleSmuggler Exfiltration Domain (checkout-cdn.com)"; flow:to_server; dns.query; content:"checkout-cdn.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-12; sid:2026750007; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - StyleSmuggler GraphQL Exploitation Attempt with styles Parameter"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/graphql"; fast_pattern; http.uri.raw; content:"styles%5B"; classtype:web-application-attack; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-12; sid:2026750008; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - StyleSmuggler Web Shell Access via X-Cache-Token Header"; flow:established,to_server; http.method; content:"POST"; http.request_header; content:"X-Cache-Token"; content:"fced27f6d57702565353ecc11722533b"; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created_at 2026-09-12; sid:2026750009; rev:1;)
```

<!-- audit: Suricata binary not available in environment for compile validation; rules follow Suricata 7.x dot-notation syntax per reference doc. DNS rules use dns.query sticky buffer with exact domain content matches — high confidence, zero FP expected for these typosquat domains. HTTP rules use http.method, http.uri, http.uri.raw, and http.request_header buffers. SID range 2026750001-2026750009 chosen to avoid conflicts. The styles%5B content match targets URL-encoded styles[ in the raw URI. The X-Cache-Token rule matches the specific MD5 authentication token used by the web shell. -->

### Snort 3: StyleSmuggler Exploitation and Web Shell Access (2 rules)

compile: not validated (snort binary not available) | confidence: medium

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - StyleSmuggler CVE-2026-75650 GraphQL Exploitation Attempt"; flow:established, to_server; http_method; content:"POST"; http_uri; content:"/graphql", fast_pattern; http_raw_uri; content:"styles%5B"; classtype:web-application-attack; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created 2026-09-12; sid:2026750101; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - StyleSmuggler Web Shell X-Cache-Token Access"; flow:established, to_server; http_method; content:"POST"; http_header; content:"X-Cache-Token", fast_pattern; content:"fced27f6d57702565353ecc11722533b"; classtype:trojan-activity; reference:url,sansec.io/research/stylesmuggler-0day; reference:cve,2026-75650; metadata:author Actioner, created 2026-09-12; sid:2026750102; rev:1;)
```

<!-- audit: Snort 3 binary not available in environment for compile validation; rules use Snort 3 underscore-notation sticky buffers (http_method, http_uri, http_raw_uri, http_header) and comma-separated content modifiers per reference doc. Confidence lowered to medium because Snort 3 does not have dns.query sticky buffer (DNS C2 rules omitted for Snort). The http_header buffer for X-Cache-Token searches across all headers; Snort 3 supports http_header:field for named header access but the exact syntax varies by deployment. -->

## Lessons Learned

1. **Template engines as attack surface**: StyleSmuggler is the second major Magento template injection exploit (after CosmicSting). Magento's tight coupling between its template engine, dependency-injection compiler, and email rendering pipeline creates a deep, hard-to-audit attack surface. E-commerce platforms should treat template compilation code paths with the same scrutiny as authentication and authorization code.

2. **The 3-day zero-day window matters**: Attackers had a 3-day head start before any patch existed, and the threat actor shipped three distinct backdoor variants within that window (demonstrating active development). Organizations relying on vendor patches alone were exposed. Virtual patching (WAF rules, `disable_functions`, `noexec` mounts) provided meaningful mitigation during the gap — these hardening measures should be pre-positioned, not deployed reactively.

3. **Protocol impersonation defeats basic monitoring**: The Rust backdoor's NTP-shaped C2 traffic on UDP port 123 will evade most HTTP-focused IDS/IPS deployments. Defenders should monitor for non-NTP hosts generating UDP/123 traffic, and validate NTP traffic against expected NTP server lists. The broader lesson: attackers increasingly use protocol impersonation to blend into allowed traffic — deep packet inspection and behavioral baselines are necessary.

## Sources

- [Sansec Research: StyleSmuggler 0-day](https://sansec.io/research/stylesmuggler-0day) — primary technical analysis with IOCs, malware samples, exploitation details, and detection commands
- [The Hacker News: Adobe Patches Magento Zero-Day](https://thehackernews.com/2026/09/adobe-patches-magento-zero-day.html) — patch release coverage, CISA KEV addition, affected versions, concurrent Adobe vulnerabilities
- [The Hacker News: Unpatched Magento and Adobe Commerce Zero-Day](https://thehackernews.com/2026/09/unpatched-magento-and-adobe-commerce.html) — early reporting during pre-patch exploitation window, Disrex/ProxiBlue unofficial patches, detailed IOCs
- [DEV Community: StyleSmuggler Analysis](https://dev.to/etairos/stylesmuggler-magento-zero-day-cve-2026-75650-drops-a-rust-backdoor-and-a-php-web-shell-1ke8) — consolidated IOC listing, remediation steps, detection commands
- [SecurityWeek: Adobe Patches Over 170 Vulnerabilities](https://www.securityweek.com/adobe-patches-over-170-vulnerabilities-including-commerce-zero-day/) — broader Adobe patch context, APSB26-146 details
- [eSecurity Planet: CVE-2026-75650 Patch Guide](https://www.esecurityplanet.com/threats/news-adobe-commerce-cve-2026-75650-stylesmuggler/) — remediation guidance and IOC hunting procedures

---
*Report generated by Actioner*
