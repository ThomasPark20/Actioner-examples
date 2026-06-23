<!-- revision: v1.1 2026-06-23 — Applied critic NEEDS-REVISION verdict. Changes: (1) YARA Exfiltration_Payload: removed generic $totp_steal string, downgraded High->Medium. (2) YARA Webshell_Indicators: $hidden_admin now requires conjunction with $c2_domain or $suspicious*; $sp_option branch tightened to require both options plus $suspicious*. (3) Sigma Web Shell: removed selection_tools arm (tinyfilemanager/adminer FPs), downgraded High->Medium. (4) Snort SID 2100001: rewrote to use dest IP in rule header instead of payload content match. (5) Snort SID 2100003 / Suricata SID 2200002: added singular/plural naming caveat, downgraded to Medium. (6) Snort SID 2100005 / Suricata SID 2200005: fixed CVE reference from CVE-2026-10735 to CVE-2026-49777. (7) Snort metadata: standardized created->created_at across all SIDs. (8) ATT&CK: T1140->T1070.004 (File Deletion); T1078.001->T1556 (Modify Authentication Process). (9) CVE note added clarifying CVE-2026-49777 vs CVE-2026-10735. All changed rules re-validated. -->
# Technical Analysis Report: ShapedPlugin WordPress Pro Plugins Supply Chain Attack (2026-06-23)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-23
Version: 1.1 (REVISED)

## Executive Summary

Threat actors compromised ShapedPlugin's build and distribution pipeline and injected a multi-stage backdoor into premium WordPress plugin updates distributed through the vendor's official Easy Digital Downloads (EDD) infrastructure at account.shapedplugin[.]com. The attack, disclosed by Wordfence on June 12, 2026, affected at least three Pro plugins -- Product Slider Pro for WooCommerce (CVE-2026-49777, CVSS 10.0), Real Testimonials Pro, and Smart Post Show Pro -- with a combined exposure window from April to June 2026. Free versions hosted on WordPress.org were not compromised.

The backdoor operates in two stages: an initial self-deleting loader (`LicenseLoader.php`) that fetches a second-stage payload from a C2 server at 194.76.217[.]28:2871, which then deploys as a hidden fake plugin (`woocommerce-subscription` or `woocommerce-notification`). The payload bundles Tiny File Manager 2.6, Adminer 5.1, a web shell, a REST API backdoor for arbitrary file writes, credential-stealing components that intercept WordPress authentication events, and a 2FA secret exfiltration module targeting TOTP seeds from WP 2FA, Wordfence Login Security, Really Simple SSL 2FA, and the Two-Factor plugin. Stolen data is exfiltrated to generate.2faplugin[.]org and cdn-stats-api[.]com. A hardcoded MD5 hash enables password-less administrator authentication, and a hidden admin account (`wp_support_sys`) provides persistent access. With over 430,000 free installations across ShapedPlugin's product line, the blast radius of the Pro-tier compromise is significant for high-value WordPress sites.

## Background: ShapedPlugin WordPress Plugin Ecosystem

ShapedPlugin, LLC is a WordPress plugin vendor that develops both free and premium (Pro) versions of several popular plugins, including Product Slider for WooCommerce, Real Testimonials, Smart Post Show, Logo Carousel, Post Slider, and WP Tabs. The free versions are distributed through WordPress.org's plugin directory, while Pro versions are distributed through ShapedPlugin's own infrastructure using Easy Digital Downloads (EDD) for licensing and updates. The combined free installation base exceeds 430,000 sites, and the Pro versions serve a subset of higher-value commercial WordPress deployments.

The vendor's CI/CD pipeline and EDD update server became the attack surface, making this a classic software supply chain compromise where trust in the vendor's official distribution channel was weaponized against end users.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| April 2026 (est.) | Earliest potential distribution of backdoored Pro plugin updates |
| 2026-05-10 | Exfiltration domain generate.2faplugin[.]org configured/updated |
| 2026-05-21 | Four files modified within a two-hour window in the build pipeline (automated injection indicator) |
| 2026-06-05 | CVE-2026-49777 published for Product Slider Pro for WooCommerce |
| 2026-06-10 | First customer reports of suspicious activity from plugin updates |
| 2026-06-11 | Wordfence Threat Intelligence team notified of suspicious activity |
| 2026-06-12 | Wordfence confirms backdoored Real Testimonials Pro 3.2.5 and publishes PSA |
| 2026-06-17 | CVE-2026-49777 NVD entry last modified |

## Root Cause: Build Pipeline Compromise

Attackers gained access to ShapedPlugin's build and distribution pipeline -- specifically the CI/CD infrastructure responsible for packaging Pro plugin releases and the EDD update server at account.shapedplugin[.]com. Forensic evidence supporting this conclusion includes: only four files were modified within a two-hour window on May 21, 2026, suggesting an automated injection process rather than manual tampering. The attackers selectively backdoored only Pro (premium) plugins, likely to avoid the more rigorous review processes on WordPress.org and to target higher-value victims who pay for commercial licenses.

The exact initial access vector into ShapedPlugin's infrastructure (credential theft, vulnerability exploitation, or insider compromise) has not been publicly disclosed as of the report date.

## Technical Analysis of the Malicious Payload

### 1. Stage 1: LicenseLoader.php (Initial Loader)

The compromised Pro plugin packages contained a malicious file named `LicenseLoader.php` that was automatically loaded within the WordPress admin panel context -- triggering on every admin page visit. Upon execution, the loader:

1. **Contacts the C2 server** at `194.76.217[.]28:2871` to download the second-stage payload
2. **Installs the payload** as a fake plugin in the WordPress plugin directory
3. **Reports the victim's domain** back to the C2 server for attacker tracking
4. **Self-deletes** to hinder forensic analysis and incident response

This self-erasing behavior means the initial infection vector disappears after first execution, making post-compromise detection of the initial access more difficult.

### 2. Stage 2: Fake WooCommerce Plugin (Persistent Backdoor)

The downloaded payload disguises itself as a legitimate WooCommerce extension, using one of two names:
- `woocommerce-subscription` (mimicking WooCommerce Subscriptions)
- `woocommerce-notification` (mimicking WooCommerce notification plugins)

The fake plugin is **hidden from the WordPress admin plugin list**, preventing administrators from discovering it through normal WordPress management interfaces.

The payload bundles multiple attacker tools:

| Component | Version | Purpose |
|-----------|---------|---------|
| Tiny File Manager | 2.6 | GUI-based file management for browsing/uploading/editing files on the server |
| Adminer | 5.1 | Database administration tool providing full read/write access to the WordPress database |
| Web shell | - | Command execution via URL parameters |
| REST API backdoor | - | Custom REST endpoint accepting arbitrary file writes via authentication token |
| Credential stealer | - | Intercepts WordPress authentication events |
| Login bypass | - | Hardcoded MD5 hash enabling password-less admin authentication |

Additional suspicious files deployed to `wp-content/plugins/`:
- `class-wp-cache-manager.php`
- `init-core-helper.php`
- `wp-db-update.php`

A hidden administrator account named `wp_support_sys` is created for persistent access.

### 3. C2 Infrastructure

| Indicator | Value | Role |
|-----------|-------|------|
| C2 Server IP | 194.76.217[.]28 | Stage 2 payload download and victim domain reporting |
| C2 Port | 2871 | Non-standard port for C2 communication |
| Exfil Domain | generate.2faplugin[.]org | 2FA secret and credential exfiltration |
| C2 Domain | cdn-stats-api[.]com | Credential staging and exfiltration endpoint |
| Hosting Provider | AEZA GROUP LLC | Russian-based hosting provider for C2 infrastructure |

The exfiltration domain generate.2faplugin[.]org was updated on May 10, 2026, five days before the first confirmed build pipeline modifications on May 21.

### 4. Data Exfiltration via install-persistent.php

The `install-persistent.php` component exfiltrates the following data categories:

| Data Category | Details |
|---------------|---------|
| WordPress Configuration | Full `wp-config.php` contents including DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, authentication salts, and debug settings |
| Administrator Accounts | All admin usernames with registration dates |
| Authentication Credentials | Intercepted usernames, passwords, session cookies, IP addresses, browser details, and user privilege levels |
| Mail Plugin Credentials | SMTP credentials from WP Mail SMTP, Post SMTP, and Easy WP SMTP |
| 2FA Secrets | TOTP seed values from WP 2FA, Wordfence Login Security, Really Simple SSL 2FA, and Two-Factor plugin |
| WooCommerce Data | Order data from the previous 3 months including payment breakdowns |

### 5. Anti-Forensics / Evasion Techniques

- **Self-deletion**: `LicenseLoader.php` erases itself after first execution, removing the initial infection evidence
- **Plugin hiding**: The fake WooCommerce plugin is hidden from the WordPress admin plugin list
- **Legitimate naming**: Disguises malware as WooCommerce extensions and WordPress core utility files
- **Selective targeting**: Only Pro plugins backdoored (avoiding WordPress.org review processes)
- **Automated injection**: Four files modified within a two-hour window, suggesting CI/CD pipeline automation
- **Suspicious wp_options entries**: Database persistence using prefixes `_wp_sp_` and `_tmp_sp` in the `wp_options` table

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `generate.2faplugin[.]org`)
> - IP addresses: `[.]` replacing dots (e.g., `194.76.217[.]28`)

### Package / Software Level

| Package / Component | Malicious Version | Clean Version | Description |
|---------------------|-------------------|---------------|-------------|
| Product Slider Pro for WooCommerce | < 3.5.4 (confirmed 3.5.2) | 3.5.4 | Backdoored via supply chain, CVE-2026-49777 (CVSS 10.0) |
| Real Testimonials Pro | 3.2.4 | 3.2.5 | Backdoored via supply chain |
| Smart Post Show Pro | 4.0.1 | 4.0.2 | Backdoored via supply chain |

> **CVE Note:** Multiple CVE identifiers appear in public reporting for this campaign. CVE-2026-49777 (CVSS 10.0) is the NVD-assigned identifier for the Product Slider Pro for WooCommerce backdoor. Some sources (e.g., Threat-Modeling.com, Mallory.ai) also reference CVE-2026-10735, which may cover additional affected plugins or a separate aspect of the vulnerability. All detection rules in this report are standardized on CVE-2026-49777 as the primary reference.

### File System

| Path | Description |
|------|-------------|
| `wp-content/plugins/<plugin>/LicenseLoader.php` | Stage 1 self-deleting loader |
| `wp-content/plugins/woocommerce-subscription/` | Fake plugin directory (Stage 2 payload) |
| `wp-content/plugins/woocommerce-notification/` | Fake plugin directory (Stage 2 payload) |
| `wp-content/plugins/*/class-wp-cache-manager.php` | Suspicious backdoor component |
| `wp-content/plugins/*/init-core-helper.php` | Suspicious backdoor component |
| `wp-content/plugins/*/wp-db-update.php` | Suspicious backdoor component |
| `install-persistent.php` | Data exfiltration script |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 194.76.217[.]28:2871 | C2 server for payload download and victim reporting |
| Domain | generate.2faplugin[.]org | 2FA secret and credential exfiltration |
| Domain | cdn-stats-api[.]com | Credential staging and exfiltration |
| Domain | account.shapedplugin[.]com | Compromised vendor EDD update server |

### Behavioral

- WordPress plugin directory contains `woocommerce-subscription` or `woocommerce-notification` directories that are not visible in the WordPress admin plugin list
- Hidden administrator account `wp_support_sys` exists in the `wp_users` table
- Suspicious `wp_options` table entries with prefixes `_wp_sp_` or `_tmp_sp`
- Outbound connections from the web server on port 2871
- Web server process spawning shell commands via web shell URL parameters

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attackers compromised ShapedPlugin's build pipeline and EDD update server to inject malware into Pro plugin updates |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Web shell component accepts URL parameter commands for execution on the server |
| T1505.003 | Server Software Component: Web Shell | Deployment of web shell, Tiny File Manager, and Adminer for persistent server access |
| T1556 | Modify Authentication Process | Hardcoded MD5 hash enabling password-less admin login bypasses WordPress authentication |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication over HTTP to generate.2faplugin[.]org and cdn-stats-api[.]com |
| T1105 | Ingress Tool Transfer | LicenseLoader.php downloads second-stage payload from C2 server |
| T1041 | Exfiltration Over C2 Channel | Credentials, 2FA secrets, wp-config.php, and WooCommerce data exfiltrated to C2 domains |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | TOTP seed exfiltration from WP 2FA, Wordfence Login Security, Really Simple SSL 2FA, and Two-Factor plugin |
| T1136.001 | Create Account: Local Account | Creation of hidden `wp_support_sys` administrator account |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | Fake plugin hidden from WordPress admin interface |
| T1070.004 | Indicator Removal: File Deletion | Self-deleting LicenseLoader.php removes evidence of initial infection |

## Impact Assessment

- **Breadth**: Over 430,000 free installations exist across ShapedPlugin's product portfolio; the Pro-tier subset receiving backdoored updates is smaller but represents higher-value commercial WordPress sites. At least three Pro plugins were confirmed compromised.
- **Depth**: Full site takeover capability -- database credentials, admin access, file system access, and credential theft including 2FA secrets. The combination of Adminer + Tiny File Manager + web shell provides complete server-side control.
- **Stealth**: Self-deleting initial loader, hidden fake plugins, and use of legitimate-looking file names make detection difficult without targeted scanning. The two-month exposure window (April-June 2026) provided extended dwell time.
- **Data Impact**: Exfiltration of wp-config.php (database credentials and authentication salts), all admin credentials, mail/SMTP credentials, TOTP 2FA secrets, and three months of WooCommerce order data (including payment information).

## Detection & Remediation

### Immediate Detection

Defenders can run the following checks on WordPress installations:

```bash
# Check for fake WooCommerce plugin directories
ls -la wp-content/plugins/woocommerce-subscription/ 2>/dev/null
ls -la wp-content/plugins/woocommerce-notification/ 2>/dev/null

# Check for suspicious PHP files
find wp-content/plugins/ -name "LicenseLoader.php" -o -name "class-wp-cache-manager.php" \
    -o -name "init-core-helper.php" -o -name "wp-db-update.php" \
    -o -name "install-persistent.php" 2>/dev/null

# Check for hidden admin account
wp user list --role=administrator --fields=ID,user_login,user_registered | grep wp_support_sys

# Check wp_options for suspicious entries
wp db query "SELECT option_name, option_value FROM wp_options WHERE option_name LIKE '_wp_sp_%' OR option_name LIKE '_tmp_sp%';"

# Check for outbound connections to C2
netstat -an | grep -E '194\.76\.217\.28|:2871'
```

### Remediation

1. **Immediate containment**: Block outbound connections to 194.76.217[.]28, generate.2faplugin[.]org, and cdn-stats-api[.]com at the firewall
2. **Remove backdoor components**: Delete the fake plugin directories (`woocommerce-subscription`, `woocommerce-notification`) and suspicious PHP files
3. **Remove hidden admin account**: Delete the `wp_support_sys` user account
4. **Clean wp_options**: Remove entries with `_wp_sp_` and `_tmp_sp` prefixes
5. **Rotate ALL credentials**:
   - All WordPress user passwords
   - Database credentials (DB_USER/DB_PASSWORD in wp-config.php)
   - WordPress authentication salts and keys
   - SMTP credentials in mail plugins
   - Revoke and regenerate all 2FA/TOTP secrets for all users
6. **Update plugins**: Install patched versions -- Product Slider Pro >= 3.5.4, Smart Post Show Pro >= 4.0.2, Real Testimonials Pro >= 3.2.5
7. **Audit admin accounts**: Review all administrator accounts for unauthorized additions
8. **Review WooCommerce data**: Assess exposure of customer order and payment data for breach notification obligations

### Long-Term Hardening

- Implement file integrity monitoring (FIM) on WordPress plugin directories
- Deploy web application firewalls (WAF) with rules for web shell detection
- Monitor outbound connections from web servers for non-standard ports
- Use plugin security scanning tools (Wordfence, Sucuri) with real-time threat intelligence feeds
- Consider restricting plugin auto-updates to allow manual review of update packages
- Monitor DNS queries from web server infrastructure for anomalous domain resolutions

## Detection Rules

The following rules target the specific infrastructure, file patterns, and network indicators disclosed in the ShapedPlugin supply chain attack. All rules are IOC-specific (strict/advisory altitude) and should be deployed alongside broader web shell behavioral detections for defense-in-depth. The primary caveat is that the attacker can rotate C2 infrastructure, so the network IOC rules have a limited shelf life -- the YARA file-content rules provide more durable detection.

### YARA: ShapedPlugin LicenseLoader Backdoor Detection

Detects the Stage 1 LicenseLoader.php initial loader via the combination of the loader name and known C2/payload indicators in PHP files.

**Status:** Compiled ✅ | Confidence: High

<!-- audit: yarac exit 0. Targets PHP files containing "LicenseLoader" plus at least one of the known C2 IP, port, or fake plugin names. Strict conjunction prevents matching on benign files containing any single string. No defanged values in rule. -->

```yara
rule ShapedPlugin_LicenseLoader_Backdoor
{
    meta:
        description = "Detects the ShapedPlugin LicenseLoader.php initial loader used in the supply chain attack (CVE-2026-49777)"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html"
        severity = "critical"

    strings:
        $loader_name = "LicenseLoader" ascii
        $c2_ip = "194.76.217.28" ascii
        $c2_port = "2871" ascii
        $fake_plugin1 = "woocommerce-subscription" ascii
        $fake_plugin2 = "woocommerce-notification" ascii
        $php_tag = "<?php" ascii

    condition:
        $php_tag and $loader_name and ($c2_ip or $c2_port or $fake_plugin1 or $fake_plugin2)
}
```

### YARA: ShapedPlugin Credential Exfiltration Payload

Detects the Stage 2 credential-stealing payload that targets wp-config.php and 2FA secrets, exfiltrating to the known domain.

**Status:** Compiled ✅ | Confidence: Medium

<!-- revision: removed $totp_steal ("totp") from strings and condition -- too generic, matches legitimate 2FA code. Downgraded confidence High->Medium. Now requires fake plugin name as second factor. -->
<!-- audit: yarac exit 0. Requires PHP tag, exfil domain OR (install-persistent.php AND wp-config.php), AND at least one of the fake plugin names. Multi-factor condition minimizes FPs. -->

```yara
rule ShapedPlugin_Exfiltration_Payload
{
    meta:
        description = "Detects the ShapedPlugin credential-stealing payload targeting wp-config.php and 2FA secrets"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html"
        severity = "high"

    strings:
        $exfil_domain = "generate.2faplugin.org" ascii
        $install_persist = "install-persistent.php" ascii
        $wp_config_read = "wp-config.php" ascii
        $fake_plugin1 = "woocommerce-subscription" ascii
        $fake_plugin2 = "woocommerce-notification" ascii
        $php_tag = "<?php" ascii

    condition:
        $php_tag and ($exfil_domain or ($install_persist and $wp_config_read)) and ($fake_plugin1 or $fake_plugin2)
}
```

### YARA: ShapedPlugin Web Shell and Attacker Tool Indicators

Detects web shell components and attacker tools (Tiny File Manager, Adminer, hidden admin account) associated with the Stage 2 payload.

**Status:** Compiled ✅ | Confidence: Medium

<!-- revision: $hidden_admin standalone branch was too broad -- now requires conjunction with $c2_domain or a $suspicious* file. $sp_option1 branch tightened to require both $sp_option1 AND $sp_option2 plus a $suspicious* file, preventing lone wp_options prefix matches. -->
<!-- audit: yarac exit 0. Broader rule matching tool combinations, hidden admin account (with corroborating IOC), C2 domain, or suspicious file name clusters. The Tiny File Manager + Adminer conjunction alone is not malicious in isolation (both are legitimate tools), but their co-presence in a WordPress plugin directory is highly anomalous. -->

```yara
rule ShapedPlugin_Webshell_Indicators
{
    meta:
        description = "Detects web shell and attacker tool indicators associated with the ShapedPlugin supply chain backdoor"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html"
        severity = "high"

    strings:
        $tiny_fm = "Tiny File Manager" ascii
        $adminer = "Adminer" ascii
        $hidden_admin = "wp_support_sys" ascii
        $suspicious1 = "class-wp-cache-manager.php" ascii
        $suspicious2 = "init-core-helper.php" ascii
        $suspicious3 = "wp-db-update.php" ascii
        $c2_domain = "cdn-stats-api.com" ascii
        $sp_option1 = "_wp_sp_" ascii
        $sp_option2 = "_tmp_sp" ascii
        $php_tag = "<?php" ascii

    condition:
        $php_tag and (
            ($tiny_fm and $adminer) or
            ($hidden_admin and ($c2_domain or 1 of ($suspicious*))) or
            $c2_domain or
            (2 of ($suspicious*)) or
            ($sp_option1 and $sp_option2 and 1 of ($suspicious*))
        )
}
```

### Sigma: ShapedPlugin Backdoor Web Shell Access

Detects HTTP requests to web shell components deployed by the ShapedPlugin backdoor in web server access logs.

**Status:** Compiled ✅ | Confidence: Medium

<!-- revision: removed selection_tools arm (tinyfilemanager/adminer) -- these are legitimate admin tools and cause FPs when deployed standalone. Downgraded confidence High->Medium and level high->medium. Added false-positive note about singular vs plural WooCommerce Subscriptions naming. -->
<!-- audit: sigma check 0 errors 0 issues. Converts to Splunk and LogScale without error. Targets webserver access logs for URI paths matching fake plugin directories and suspicious PHP file names. No defanged values. -->

```yaml
title: ShapedPlugin Backdoor Web Shell Access via URL Parameters
id: 9c3e7a1d-4b2f-5e8d-a6c9-1f0d3b7e2a4c
status: experimental
description: >
    Detects HTTP requests to web shell components deployed by the ShapedPlugin
    supply chain backdoor, including the custom REST API backdoor disguised as
    WooCommerce plugins and suspicious PHP files dropped by the payload.
references:
    - https://securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html
    - https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html
author: Actioner
date: 2026-06-23
tags:
    - attack.t1505.003
    - attack.t1059.004
logsource:
    category: webserver
detection:
    selection_fake_plugins:
        cs-uri-stem|contains:
            - '/wp-content/plugins/woocommerce-subscription/'
            - '/wp-content/plugins/woocommerce-notification/'
    selection_suspicious_files:
        cs-uri-stem|contains:
            - 'class-wp-cache-manager.php'
            - 'init-core-helper.php'
            - 'wp-db-update.php'
            - 'install-persistent.php'
    condition: selection_fake_plugins or selection_suspicious_files
falsepositives:
    - Legitimate WooCommerce subscription or notification plugins with matching directory names (note the legitimate plugin uses plural "woocommerce-subscriptions")
level: medium
```

### Sigma: DNS Query to ShapedPlugin C2 Domains

Detects DNS resolution requests for the known exfiltration and C2 domains used by the ShapedPlugin backdoor.

**Status:** Compiled ✅ | Confidence: High

<!-- audit: sigma check 0 errors 0 issues. Converts to Splunk and LogScale. IOC-specific rule matching known attacker domains. Low FP risk as these are attacker-registered domains. Shelf life limited to domain availability. -->

```yaml
title: DNS Query to ShapedPlugin Backdoor C2 Domains
id: b7f2d8e1-3a9c-4f6b-8d5e-0c1a2b9d7f3e
status: experimental
description: >
    Detects DNS queries to known command-and-control and exfiltration domains
    used by the ShapedPlugin supply chain attack backdoor, including the 2FA
    secret exfiltration domain and the credential staging domain.
references:
    - https://securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html
    - https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html
author: Actioner
date: 2026-06-23
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '2faplugin.org'
            - 'cdn-stats-api.com'
    condition: selection
falsepositives:
    - Unlikely - these are attacker-controlled domains
level: critical
```

### Sigma: Network Connection to ShapedPlugin C2 Server

Detects outbound connections to the known C2 IP and port used by the LicenseLoader.php initial stage.

**Status:** Compiled ✅ | Confidence: High

<!-- audit: sigma check 0 errors 0 issues. Converts to Splunk and LogScale. Firewall logsource targeting specific IP:port pair. Highly specific with minimal FP. Shelf life limited to C2 infrastructure lifetime. -->

```yaml
title: Network Connection to ShapedPlugin Backdoor C2 Server
id: e4a1c6d9-8b3f-4e7a-9d2c-5f0b1a8e3c6d
status: experimental
description: >
    Detects outbound network connections to the known C2 server IP and port used
    by the ShapedPlugin LicenseLoader.php initial stage backdoor to download
    second-stage payloads.
references:
    - https://securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html
    - https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html
author: Actioner
date: 2026-06-23
tags:
    - attack.t1071.001
    - attack.t1105
logsource:
    category: firewall
detection:
    selection:
        dst_ip: '194.76.217.28'
        dst_port: 2871
    condition: selection
falsepositives:
    - Unlikely - this IP and port combination is specific to the attacker C2
level: critical
```

### Snort: ShapedPlugin C2 and Exfiltration Detection (5 rules)

Five Snort 2.x rules detecting C2 communication on port 2871, exfiltration to 2faplugin[.]org, fake WooCommerce plugin HTTP requests, and cdn-stats-api[.]com C2 traffic. Note: SID 2100003 (`woocommerce-subscription`, singular) may match environments running the legitimate WooCommerce Subscriptions plugin if its directory name is similar -- the legitimate plugin uses plural `woocommerce-subscriptions`.

**Status:** Compiled ✅ | Confidence: Medium-High (see per-rule caveats)

<!-- revision: SID 2100001 rewritten -- moved C2 IP from content match (IP is in network header, not payload) to destination IP in rule header, matching Suricata SID 2200006 approach. SID 2100003 msg updated to note singular "woocommerce-subscription" (the legitimate plugin is plural "woocommerce-subscriptions"); downgraded to Medium due to naming overlap risk. SID 2100005 fixed CVE reference from CVE-2026-10735 to CVE-2026-49777 for consistency. All SIDs: standardized metadata key to created_at. Bumped rev on changed SIDs. -->
<!-- audit: snort -T exit 0. All 5 rules validated against Snort 2.9.20 with /etc/snort/snort.conf. Uses $HOME_NET/$EXTERNAL_NET variables, flow:established for TCP rules, and fast_pattern on primary content matches. SIDs 2100001-2100005. -->

```
alert tcp $HOME_NET any -> 194.76.217.28 2871 (msg:"Actioner - ShapedPlugin Backdoor C2 Communication to 194.76.217.28:2871"; flow:established,to_server; classtype:trojan-activity; reference:url,securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html; reference:cve,2026-49777; metadata:author Actioner, created_at 2026-06-23; sid:2100001; rev:2;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - ShapedPlugin Backdoor Exfiltration to 2faplugin.org"; flow:established,to_server; content:"generate.2faplugin.org"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html; reference:cve,2026-49777; metadata:author Actioner, created_at 2026-06-23; sid:2100002; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - ShapedPlugin Backdoor Fake WooCommerce Plugin Request (woocommerce-subscription singular)"; flow:established,to_server; content:"/wp-content/plugins/woocommerce-subscription/"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html; reference:cve,2026-49777; metadata:author Actioner, created_at 2026-06-23; sid:2100003; rev:2;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - ShapedPlugin Backdoor Fake WooCommerce Notification Plugin"; flow:established,to_server; content:"/wp-content/plugins/woocommerce-notification/"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html; reference:cve,2026-49777; metadata:author Actioner, created_at 2026-06-23; sid:2100004; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - ShapedPlugin Backdoor C2 Domain cdn-stats-api.com"; flow:established,to_server; content:"cdn-stats-api.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,threat-modeling.com/shapedplugin-wordpress-update-flow-supply-chain-attack-june-2026/; reference:cve,2026-49777; metadata:author Actioner, created_at 2026-06-23; sid:2100005; rev:2;)
```

### Suricata: ShapedPlugin C2, Exfiltration, and DNS Detection (6 rules)

Six Suricata 7.x rules using dot-notation sticky buffers for HTTP host/URI matching, DNS query detection for both C2 domains, and a direct TCP rule for the C2 IP:port. Note: SID 2200002 (`woocommerce-subscription`, singular) may overlap with the legitimate WooCommerce Subscriptions plugin (plural `woocommerce-subscriptions`) -- verify directory naming in your environment before deployment.

**Status:** Compiled ✅ | Confidence: Medium-High (see per-rule caveats)

<!-- revision: SID 2200002 msg updated to note singular naming -- the legitimate WooCommerce plugin is "woocommerce-subscriptions" (plural); downgraded to Medium confidence due to naming overlap. SID 2200005 fixed CVE reference from CVE-2026-10735 to CVE-2026-49777 for consistency across all rules. Bumped rev on changed SIDs. -->
<!-- audit: suricata -T exit 0 on Suricata 7.0.3. All 6 rules validated. Uses http.host, http.uri, dns.query dot-notation buffers. SIDs 2200001-2200006. No underscore (Snort) syntax. -->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ShapedPlugin Backdoor Exfiltration to generate.2faplugin.org"; flow:established,to_server; http.host; content:"generate.2faplugin.org"; fast_pattern; classtype:trojan-activity; reference:url,securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html; reference:cve,2026-49777; metadata:author Actioner, created_at 2026-06-23; sid:2200001; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ShapedPlugin Backdoor Fake WooCommerce-Subscription Plugin Access (singular)"; flow:established,to_server; http.uri; content:"/wp-content/plugins/woocommerce-subscription/"; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html; reference:cve,2026-49777; metadata:author Actioner, created_at 2026-06-23; sid:2200002; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ShapedPlugin Backdoor Fake WooCommerce-Notification Plugin Access"; flow:established,to_server; http.uri; content:"/wp-content/plugins/woocommerce-notification/"; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html; reference:cve,2026-49777; metadata:author Actioner, created_at 2026-06-23; sid:2200003; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ShapedPlugin Backdoor DNS Query to 2faplugin.org Exfil Domain"; dns.query; content:"2faplugin.org"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html; reference:cve,2026-49777; metadata:author Actioner, created_at 2026-06-23; sid:2200004; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - ShapedPlugin Backdoor DNS Query to cdn-stats-api.com C2 Domain"; dns.query; content:"cdn-stats-api.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html; reference:cve,2026-49777; metadata:author Actioner, created_at 2026-06-23; sid:2200005; rev:2;)

alert tcp $HOME_NET any -> 194.76.217.28 2871 (msg:"Actioner - ShapedPlugin Backdoor C2 Connection to 194.76.217.28:2871"; flow:established,to_server; classtype:trojan-activity; reference:url,securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html; reference:cve,2026-49777; metadata:author Actioner, created_at 2026-06-23; sid:2200006; rev:1;)
```

## Lessons Learned

1. **Premium plugin distribution channels are high-value targets**: Unlike free plugins on WordPress.org which undergo automated code scanning, premium plugins distributed through vendor-hosted EDD systems lack centralized security review, making them attractive supply chain targets.

2. **Self-deleting loaders complicate incident response**: The `LicenseLoader.php` self-deletion pattern means that by the time a compromise is investigated, the initial infection vector has already been erased. Organizations should implement file integrity monitoring that captures pre-deletion state.

3. **2FA is only as secure as its secret storage**: The targeted exfiltration of TOTP seeds from four popular 2FA plugins demonstrates that 2FA is not a silver bullet -- if the shared secret is compromised, the second factor provides no additional protection. Hardware security keys (FIDO2/WebAuthn) that do not expose exportable secrets would mitigate this specific attack vector.

4. **Selective targeting evades broad detection**: By only backdooring Pro plugins (smaller, paying user base) rather than the free versions (larger, more scrutinized), the attackers maintained a lower detection profile for approximately two months.

## Sources

- [Security Affairs - ShapedPlugin Supply Chain Attack](https://securityaffairs.com/194059/hacking/shapedplugin-supply-chain-attack-backdoors-pro-plugin-updates.html) -- Initial reporting with technical overview and Wordfence attribution
- [The Hacker News - ShapedPlugin WordPress Pro Plugins Backdoored](https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html) -- Detailed technical analysis including affected versions, CVE assignments, and exfiltration capabilities
- [Wordfence PSA - Supply Chain Compromise Targets ShapedPlugin](https://www.wordfence.com/blog/2026/06/psa-supply-chain-compromise-targets-shapedplugin-backdoored-pro-plugins-distributed-via-official-channels/) -- Primary vendor research and disclosure (content not fully accessible at time of analysis)
- [CyberInsider - Supply Chain Attack Injects Backdoor](https://cyberinsider.com/supply-chain-attack-injects-backdoor-on-shapedplugin-wordpress-software/) -- Additional reporting with 2FA plugin targeting details and Adminer version confirmation
- [NVD - CVE-2026-49777](https://nvd.nist.gov/vuln/detail/CVE-2026-49777) -- CVSS 10.0 scoring and CWE classification for Product Slider Pro for WooCommerce
- [Threat-Modeling.com - ShapedPlugin WordPress Update Flow Compromised](https://threat-modeling.com/shapedplugin-wordpress-update-flow-supply-chain-attack-june-2026/) -- Additional IOCs including cdn-stats-api[.]com, suspicious file names, hidden admin account, and wp_options indicators
- [CtrlAltNod - ShapedPlugin Supply Chain Attack](https://www.ctrlaltnod.com/news/shapedplugin-supply-chain-attack-backdoors-wordpress-pro-plugins/) -- Confirmed affected versions for Smart Post Show Pro 4.0.1 and Real Testimonials Pro 3.2.4
- [Mallory.ai - Backdoored ShapedPlugin Pro Updates](https://www.mallory.ai/stories/019ed184-ee94-7d70-8aa1-d32b2e0290f6) -- Clean version confirmation and CVE-2026-10735 details

---
*Report generated by Actioner*
