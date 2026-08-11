# Technical Analysis Report: BdThemes WordPress Plugins Supply Chain Attack (2026-08-11)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-11
Version: 1.0

## Executive Summary

Attackers compromised BdThemes' cloud storage infrastructure (a DigitalOcean Spaces bucket fronted by Cloudflare) and poisoned a static JSON data feed consumed by a promotional banner component ("Biggopti") embedded in seven popular WordPress plugins with a combined install base exceeding 100,000 sites. The poisoned JSON exploited an unescaped XSS vulnerability in the `display_id` parameter (introduced March 1, 2026 in Prime Slider v4.1.9) to inject malicious JavaScript that silently executes in any logged-in administrator's browser session. The payload (w2.js) contacts the C2 server at `ia-cdn[.]com/fz/c`, creates rogue administrator accounts via the WordPress REST API, installs a fake plugin containing the `emer-run.php` webshell, and deploys two must-use plugin backdoors for persistent unauthenticated access and stealth. No plugin source code was modified -- this was purely a data-plane supply chain attack. The campaign was active from as early as June 23, 2026 and was detected by Wordfence on August 7, 2026. WordPress.org removed all affected plugins on August 8. The C2 infrastructure is linked by Wordfence to the same threat actors behind the ARVE backdoor (CVE-2026-18072) and OptinMonster/TrustPulse script-tampering incidents.

## Background: BdThemes WordPress Plugin Ecosystem

BdThemes is a WordPress plugin vendor whose products extend Elementor page builder functionality. Their plugin suite includes Element Pack (100,000+ active installations), Prime Slider, Pixel Gallery, Ultimate Post Kit, Ultimate Store Kit, Live Copy Paste, and Smart Admin Assistant. All plugins share a common internal library called "Biggop Library" which includes the "Biggopti" component -- a promotional banner system that fetches JSON data from BdThemes' remote API infrastructure hosted on DigitalOcean Spaces and displays it within the WordPress admin dashboard. This shared library became the single point of failure exploited in this attack.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-03-01 | XSS vulnerability introduced in Prime Slider v4.1.9 via unescaped `display_id` parameter in Biggopti component |
| 2026-03 - 2026-05 | Vulnerability propagated to other BdThemes plugins sharing the Biggop Library |
| 2026-05-xx | BdThemes added a sanitizer to a neighboring field but left the flawed `display_id` HTML attribute unpatched |
| 2026-06-23 | Earliest possible start date of the active campaign (based on Wordfence assessment) |
| 2026-08-07 | Wordfence/Defiant detects attacks via Wordfence WAF; notifies WordPress.org |
| 2026-08-08 | WordPress.org removes all affected BdThemes plugins from the directory; poisoned API endpoints cleaned and serving clean JSON |
| 2026-08-10 | BleepingComputer publishes initial report; no official statement from BdThemes vendor |

## Root Cause: Poisoned Remote JSON Data Feed via Compromised Cloud Storage

The attacker gained write access to BdThemes' DigitalOcean Spaces object storage bucket that hosted the static JSON data consumed by the Biggopti promotional banner component. This was not a code-level supply chain compromise -- no plugin files in the WordPress.org repository were modified. Instead, the attacker exploited a data-plane vector: the poisoned JSON response was served to every WordPress admin dashboard that loaded any affected BdThemes plugin. The XSS vulnerability in how Biggopti handled the `display_id` field (insufficient output escaping when concatenating into an HTML `id` attribute) allowed the injected JSON content to break out of the attribute context and execute arbitrary JavaScript.

## Technical Analysis of the Malicious Payload

### 1. Initial Vector: Poisoned JSON Feed via XSS

The Biggopti component fetches promotional banners from the BdThemes API ("Sigmative API") and renders them in the WordPress admin dashboard. A coding flaw introduced March 1, 2026 in Prime Slider v4.1.9 left the `display_id` field from the JSON response unescaped when inserted into an HTML `id` attribute. While a neighboring field was properly sanitized, the `display_id` was concatenated directly, allowing an attacker with write access to the JSON feed to inject arbitrary JavaScript via attribute-context breakout. Because the script loads on every `wp-admin` page load, the injected code fires silently in the browser of any logged-in administrator.

### 2. JavaScript Payload: w2.js -- Session Hijacking and Account Creation

The primary payload, `w2.js`, is loaded from the C2 infrastructure and operates within the administrator's authenticated browser session:

1. **Targeting check:** Contacts `ia-cdn[.]com/fz/c` with the victim website's origin to fetch targeting instructions (determines whether the site should be processed)
2. **Rogue admin creation:** Uses the active administrator's WordPress nonce to create a new administrator account through the WordPress REST API (`/wp-json/wp/v2/users`). Rogue accounts use `@wordpress.org` email addresses or `bd_`-prefixed usernames with deterministic credentials.
3. **Fake plugin installation:** Downloads and installs a fake plugin with benign-sounding names such as `wp-smart-thumbnails`, which contains the `emer-run.php` webshell.

### 3. C2 Infrastructure

- **C2 Domain:** `ia-cdn[.]com`
- **C2 Endpoint:** `ia-cdn[.]com/fz/c` -- receives the victim site's origin for targeting
- **Protocol:** HTTPS
- **Attribution:** Wordfence assesses the C2 infrastructure connects to the same threat actors behind the Advanced Responsive Video Embedder backdoor (CVE-2026-18072) and the OptinMonster and TrustPulse script-tampering incidents from the prior two months.

### 4. Persistence: Webshell and Must-Use Plugin Backdoors

Once the fake plugin is installed, `emer-run.php` is invoked to install two Must-Use plugins (placed in `wp-content/mu-plugins/`) backdated to September 2025 to avoid suspicion:

**Magic-Login Backdoor:** Grants unauthenticated administrative access via a `?_wplogin=<token>` URL parameter. When the parameter is present and the token matches a stored value, the backdoor calls `wp_set_auth_cookie()` and `wp_set_current_user()` to authenticate as an administrator without credentials.

**Stealth Module:** Hooks into WordPress database queries to hide the rogue administrator accounts from the admin user list. This manipulates the `WP_User_Query` to exclude compromised accounts, making detection through the WordPress admin interface difficult.

### 5. Anti-Forensics / Evasion Techniques

- No plugin source code was modified in the WordPress.org repository, evading file-integrity monitoring
- Must-use plugins backdated to September 2025 to blend in with legitimate plugin timestamps
- Database query manipulation hides rogue admin accounts from the WordPress user list UI
- Deterministic credentials suggest automated exploitation at scale
- C2 targeting check filters which sites to compromise (selective exploitation)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Element Pack Addons for Elementor | All versions with Biggop Library | Fetches poisoned JSON via Biggopti banner component |
| Prime Slider Addons for Elementor | v4.1.9+ (XSS introduced) | First plugin with the unescaped `display_id` vulnerability |
| Pixel Gallery Addons for Elementor | All versions with Biggop Library | Fetches poisoned JSON via Biggopti banner component |
| Ultimate Post Kit | All versions with Biggop Library | Fetches poisoned JSON via Biggopti banner component |
| Ultimate Store Kit | All versions with Biggop Library | Fetches poisoned JSON via Biggopti banner component |
| Live Copy Paste | All versions with Biggop Library | Fetches poisoned JSON via Biggopti banner component |
| Smart Admin Assistant | All versions with Biggop Library | Fetches poisoned JSON via Biggopti banner component |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| WordPress | `wp-content/plugins/wp-smart-thumbnails/emer-run.php` | Not published | Webshell deployed via fake plugin |
| WordPress | `wp-content/mu-plugins/<magic-login>.php` | Not published | Must-use plugin backdoor for unauthenticated admin access |
| WordPress | `wp-content/mu-plugins/<stealth>.php` | Not published | Must-use plugin for hiding rogue admin accounts |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `ia-cdn[.]com` | C2 server for targeting and payload delivery |
| URL Pattern | `hxxps://ia-cdn[.]com/fz/c` | C2 endpoint -- receives victim site origin for targeting instructions |
| URL Pattern | `hxxps://ia-cdn[.]com/w2.js` | Primary JavaScript payload delivery |

### Behavioral

- Rogue WordPress administrator accounts created with `@wordpress.org` email addresses or `bd_`-prefixed usernames
- `?_wplogin=<token>` URL parameter grants unauthenticated admin access (magic-login backdoor)
- WordPress REST API calls to `/wp-json/wp/v2/users` creating administrator accounts
- Database options `fz_emer_login_tokens` and `fz_emer_done_v1` created in the `wp_options` table
- Must-Use plugins in `wp-content/mu-plugins/` backdated to September 2025
- `WP_User_Query` hooking to hide rogue accounts from the admin user list

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attacker poisoned BdThemes' remote JSON data feed hosted on DigitalOcean Spaces, compromising the software supply chain without modifying source code |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Malicious JavaScript (w2.js) injected via XSS executes in admin browser sessions to perform account creation and plugin installation |
| T1136.001 | Create Account: Local Account | Rogue WordPress administrator accounts created via REST API using the victim admin's authenticated session |
| T1505.003 | Server Software Component: Web Shell | emer-run.php webshell deployed via fake plugin (wp-smart-thumbnails) for persistent remote command execution |
| T1556 | Modify Authentication Process | Magic-login must-use plugin backdoor bypasses WordPress authentication via URL parameter token |
| T1071.001 | Application Layer Protocol: Web Protocols | w2.js communicates with ia-cdn[.]com/fz/c over HTTPS for C2 targeting instructions |
| T1564.002 | Hide Artifacts: Hidden Users | Stealth must-use plugin hooks WordPress database queries to hide rogue administrator accounts from the user list |
| T1078.004 | Valid Accounts: Cloud Accounts | Attacker compromised cloud storage credentials to gain write access to DigitalOcean Spaces bucket |

## Impact Assessment

**Breadth:** Seven BdThemes plugins with a combined user base exceeding 100,000 active WordPress installations were affected. Every site running any of these plugins where an administrator accessed the wp-admin dashboard during the active campaign window (June 23 -- August 8, 2026) is potentially compromised.

**Depth:** Full administrative access achieved on compromised sites through rogue admin accounts and persistent backdoors. The webshell provides remote command execution, and the magic-login backdoor ensures continued access even if the rogue admin account is discovered and removed.

**Stealth:** The attack was particularly stealthy: no plugin files were modified (evading file-integrity checks), rogue accounts are hidden from the admin user list, and must-use plugins were backdated to September 2025. The campaign may have operated for up to 46 days before detection.

## Detection & Remediation

### Immediate Detection

Run these checks on any WordPress site using BdThemes plugins:

```bash
# Check for the emer-run.php webshell
find /path/to/wordpress/wp-content/plugins/ -name "emer-run.php" -type f

# Check for unexpected must-use plugins
ls -la /path/to/wordpress/wp-content/mu-plugins/

# Check for the fake plugin directory
ls -la /path/to/wordpress/wp-content/plugins/wp-smart-thumbnails/

# Check database for campaign-specific options
wp db query "SELECT * FROM wp_options WHERE option_name IN ('fz_emer_login_tokens', 'fz_emer_done_v1');"

# Check for rogue admin accounts with @wordpress.org emails or bd_ usernames
wp db query "SELECT * FROM wp_users WHERE user_email LIKE '%@wordpress.org' OR user_login LIKE 'bd_%';"

# Check for users with administrator role not in your expected list
wp user list --role=administrator --fields=ID,user_login,user_email,user_registered
```

### Remediation

1. **Immediately deactivate and remove** all BdThemes plugins (Element Pack, Prime Slider, Pixel Gallery, Ultimate Post Kit, Ultimate Store Kit, Live Copy Paste, Smart Admin Assistant)
2. **Remove rogue administrator accounts** -- check the database directly since the stealth module hides them from the admin UI: `wp db query "DELETE FROM wp_users WHERE user_email LIKE '%@wordpress.org' OR user_login LIKE 'bd_%';"`
3. **Delete the webshell and fake plugin:** Remove `wp-content/plugins/wp-smart-thumbnails/` entirely
4. **Remove must-use plugin backdoors:** Audit and remove unfamiliar files from `wp-content/mu-plugins/`
5. **Remove campaign database options:** `wp db query "DELETE FROM wp_options WHERE option_name IN ('fz_emer_login_tokens', 'fz_emer_done_v1');"`
6. **Reset all administrator credentials** -- the attacker had access via the authenticated session
7. **Rotate all secrets** (database credentials, API keys, WordPress salts in `wp-config.php`)
8. **Review web server access logs** for requests to `emer-run.php` and requests containing `_wplogin=`
9. **Block the C2 domain** `ia-cdn[.]com` at the network perimeter

### Long-Term Hardening

- Implement Content Security Policy (CSP) headers for the WordPress admin dashboard to prevent inline script execution from untrusted sources
- Monitor outbound connections from WordPress servers to detect unexpected external API calls
- Use file-integrity monitoring that covers `wp-content/mu-plugins/` and plugin directories
- Audit WordPress admin accounts on a regular schedule via database queries, not just the admin UI
- Consider restricting which plugins can make external HTTP requests from the server side
- Apply the principle of least privilege to cloud storage buckets used for plugin infrastructure

## Detection Rules

These detections target the BdThemes supply chain attack's C2 domain (`ia-cdn[.]com`), the magic-login backdoor URL parameter (`_wplogin=`), and the `emer-run.php` webshell access. PoC/advisory-specific altitude (default); all Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. Compiles does not equal fires -- verify in your pipeline with appropriate log sources.

### Sigma: C2 Communication to ia-cdn.com via Proxy Logs

Detects outbound web proxy requests to `ia-cdn.com`, the C2 domain used for targeting instructions and payload delivery.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (with -x attacktag due to proxy blocking MITRE data endpoint — not a rule issue); splunk 0; log_scale 0. c-uri field standard for proxy category. No FP expected — ia-cdn.com is campaign-specific infrastructure. -->
```yaml
title: BdThemes Supply Chain - C2 Communication to ia-cdn.com
id: 7a3f1c8e-9b2d-4e5f-a6c7-1d8e0f3b2a4c
status: experimental
description: >
    Detects outbound web requests to ia-cdn.com, the C2 domain used in the BdThemes WordPress
    plugin supply chain attack to deliver targeting instructions and malicious JavaScript payloads.
references:
    - https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/
    - https://www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1071.001
    - attack.t1195.002
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: 'ia-cdn.com'
    condition: selection
falsepositives:
    - Legitimate use of ia-cdn.com domain (unlikely given its association with this campaign)
level: high
```

### Sigma: DNS Query for C2 Domain ia-cdn.com

Detects DNS resolution of `ia-cdn.com`, the C2 domain used for w2.js payload delivery and targeting.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (-x attacktag); splunk 0; log_scale 0. QueryName with endswith covers subdomains. Campaign-specific domain — no legitimate use known. -->
```yaml
title: BdThemes Supply Chain - DNS Query for C2 Domain ia-cdn.com
id: 2b4e6f8a-1c3d-5e7f-9a0b-2d4c6e8f0a1b
status: experimental
description: >
    Detects DNS resolution of ia-cdn.com, the command and control domain used in the BdThemes
    WordPress supply chain attack to deliver w2.js payloads and targeting instructions.
references:
    - https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/
    - https://www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1071.001
    - attack.t1195.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'ia-cdn.com'
    condition: selection
falsepositives:
    - Legitimate use of ia-cdn.com domain (unlikely given its role as C2 infrastructure)
level: high
```

### Sigma: Magic Login Backdoor URL Parameter (_wplogin)

Detects HTTP requests containing the `_wplogin=` URL parameter used by the must-use plugin backdoor for unauthenticated admin access.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (-x attacktag); splunk 0; log_scale 0. cs-uri-query standard for webserver category. _wplogin parameter name could collide with custom WordPress login plugins — downgraded to high. -->
```yaml
title: BdThemes Supply Chain - Magic Login Backdoor URL Parameter
id: 3c5f7a9b-2d4e-6f8a-0b1c-3e5d7f9a1b2c
status: experimental
description: >
    Detects HTTP requests containing the _wplogin URL parameter used by the BdThemes supply chain
    attack's must-use plugin backdoor to grant unauthenticated administrative access to compromised
    WordPress sites.
references:
    - https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/
    - https://www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1556
    - attack.t1078.004
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains: '_wplogin='
    condition: selection
falsepositives:
    - Custom WordPress plugins using a similarly named parameter (review context)
level: high
```

### Sigma: Webshell emer-run.php Access

Detects HTTP requests to `emer-run.php`, the webshell deployed through the fake wp-smart-thumbnails plugin.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (-x attacktag); splunk 0; log_scale 0. cs-uri-stem standard for webserver category. emer-run.php is a unique campaign artifact — no known legitimate use. -->
```yaml
title: BdThemes Supply Chain - Webshell emer-run.php Access
id: 4d6a8b0c-3e5f-7a9b-1c2d-4f6e8a0b2c3d
status: experimental
description: >
    Detects HTTP requests to emer-run.php, the webshell deployed by the BdThemes supply chain
    attack through a fake plugin (e.g., wp-smart-thumbnails) to maintain persistent remote access.
references:
    - https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/
    - https://www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/
author: Actioner
date: 2026/08/11
tags:
    - attack.t1505.003
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: 'emer-run.php'
    condition: selection
falsepositives:
    - Legitimate files named emer-run.php (extremely unlikely)
level: critical
```

### Snort: C2 Beacon and Payload Detection

Detects outbound HTTP traffic to `ia-cdn.com` C2 endpoints and the magic-login backdoor URL parameter.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0 (from /tmp working dir due to pidfile suffix constraint). Three rules: C2 beacon /fz/c (sid:2100101), w2.js request (sid:2100102), and _wplogin backdoor (sid:2100103). All use Snort 2.9 http_uri/http_header sticky buffers. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BdThemes Supply Chain - C2 Beacon to ia-cdn.com"; flow:established,to_server; content:"ia-cdn.com"; http_header; content:"/fz/c"; http_uri; fast_pattern; sid:2100101; rev:1; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BdThemes Supply Chain - w2.js Payload Request"; flow:established,to_server; content:"ia-cdn.com"; http_header; content:"/w2.js"; http_uri; fast_pattern; sid:2100102; rev:1; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/;)

alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"BdThemes Supply Chain - Magic Login Backdoor _wplogin Parameter"; flow:established,to_server; content:"_wplogin="; http_uri; fast_pattern; sid:2100103; rev:1; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/;)
```

### Suricata: C2 DNS, HTTP Beacon, and Backdoor Detection

Detects DNS queries to `ia-cdn.com`, HTTP beacon traffic to the `/fz/c` C2 endpoint, w2.js payload requests, and magic-login backdoor access.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Four rules: DNS C2 query (sid:2200101), HTTP C2 beacon /fz/c (sid:2200102), w2.js request (sid:2200103), _wplogin backdoor (sid:2200104). Uses Suricata 7.x dot-notation sticky buffers (dns.query, http.host, http.uri). -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - BdThemes Supply Chain C2 DNS Query for ia-cdn.com"; dns.query; content:"ia-cdn.com"; endswith; nocase; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/; reference:url,www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/; metadata: author Actioner, created_at 2026-08-11; sid:2200101; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - BdThemes Supply Chain C2 Beacon to ia-cdn.com/fz/c"; flow:established,to_server; http.host; content:"ia-cdn.com"; endswith; http.uri; content:"/fz/c"; startswith; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/; reference:url,www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/; metadata: author Actioner, created_at 2026-08-11; sid:2200102; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - BdThemes Supply Chain w2.js Payload Request"; flow:established,to_server; http.uri; content:"/w2.js"; endswith; http.host; content:"ia-cdn.com"; endswith; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/; metadata: author Actioner, created_at 2026-08-11; sid:2200103; rev:1;)

alert http any any -> $HOME_NET any (msg:"Actioner - BdThemes Supply Chain Magic Login Backdoor Access"; flow:established,to_server; http.uri; content:"_wplogin="; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/; metadata: author Actioner, created_at 2026-08-11; sid:2200104; rev:1;)
```

### YARA: Webshell, Payload, and MU-Plugin Backdoor Detection

Detects file-level artifacts from the BdThemes supply chain attack: the emer-run.php webshell, w2.js JavaScript payload, and must-use plugin backdoors.
**Status:** compile ✅ compiles · confidence: high · sample: synthetic ✓
<!-- audit: yarac exit 0. Sample test: all three rules fired on synthetic positives constructed from published campaign strings; 0 matches on negative corpus. BdThemes_Supply_Chain_Webshell_EmerRun threshold raised to 4 of them to avoid matching threat-intel documents discussing the campaign. Three rules keying on campaign-specific strings (fz_emer_login_tokens, fz_emer_done_v1, _wplogin, emer-run.php, ia-cdn.com/fz/c) — no benign overlap expected. -->
```yara
rule BdThemes_Supply_Chain_Webshell_EmerRun
{
    meta:
        description = "Detects emer-run.php webshell and persistence artifacts from the BdThemes WordPress supply chain attack"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/"
        reference2 = "https://www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/"

    strings:
        $webshell_name = "emer-run.php" ascii
        $c2_domain = "ia-cdn.com" ascii
        $c2_path = "/fz/c" ascii
        $backdoor_param = "_wplogin" ascii
        $db_option1 = "fz_emer_login_tokens" ascii
        $db_option2 = "fz_emer_done_v1" ascii
        $fake_plugin = "wp-smart-thumbnails" ascii

    condition:
        4 of them
}

rule BdThemes_Supply_Chain_W2JS_Payload
{
    meta:
        description = "Detects the w2.js JavaScript payload used in the BdThemes supply chain attack for admin account creation and webshell deployment"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/"

    strings:
        $c2_url = "ia-cdn.com/fz/c" ascii
        $wp_rest = "/wp-json/wp/v2/users" ascii
        $webshell = "emer-run" ascii
        $nonce = "wp_create_nonce" ascii
        $role = "administrator" ascii

    condition:
        $c2_url and 2 of ($wp_rest, $webshell, $nonce, $role)
}

rule BdThemes_Supply_Chain_MU_Plugin_Backdoor
{
    meta:
        description = "Detects must-use plugin backdoor components from the BdThemes supply chain attack including the magic login and stealth module"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/"

    strings:
        $login_param = "_wplogin" ascii
        $option_tokens = "fz_emer_login_tokens" ascii
        $option_done = "fz_emer_done_v1" ascii
        $mu_path = "mu-plugins" ascii
        $wp_set_auth = "wp_set_auth_cookie" ascii
        $wp_set_current = "wp_set_current_user" ascii

    condition:
        ($login_param and $option_tokens) or ($option_done and 2 of ($mu_path, $wp_set_auth, $wp_set_current))
}
```

## Lessons Learned

This attack demonstrates a novel supply chain vector that bypasses traditional code-integrity monitoring entirely. By targeting the data plane (a remote JSON feed) rather than the code plane (plugin source), the attacker avoided detection by file-integrity checkers, WordPress.org's own code review process, and hash-based verification. The shared library pattern across BdThemes' plugin ecosystem meant a single point of compromise propagated to seven plugins simultaneously. The approximately 46-day dwell time (June 23 to August 7) underscores the need for monitoring external API calls from WordPress admin contexts, not just file changes. Plugin vendors serving promotional content from remote APIs should treat those data feeds as a critical attack surface requiring the same security controls as source code repositories.

## Sources

- [BleepingComputer - BdThemes plugins supply-chain hack creates rogue WordPress admins](https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/) — primary reporting with technical details on the attack mechanism, payload, and C2 infrastructure
- [Wordfence - PSA: Supply Chain Compromise in BdThemes Ecosystem via Poisoned API Response](https://www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/) — original Wordfence/Defiant analysis and disclosure; primary source for IOCs and timeline
- [The Hacker News - BdThemes Supply Chain Attack Poisons JSON to Create Rogue WordPress Admins](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html) — detailed technical writeup with w2.js payload analysis, emer-run.php webshell details, and must-use plugin backdoor mechanisms
- [Infosecurity Magazine - WordPress Plugins Compromised Without a Single File Change](https://www.infosecurity-magazine.com/news/bdthemes-wordpress-poisoned-api/) — additional reporting on the data-plane attack vector and WordPress.org response
- [GBHackers - WordPress Supply Chain Attack Exploits BdThemes Plugins](https://gbhackers.com/wordpress-supply-chain-attack-exploits-bdthemes-plugins/) — technical details on Biggopti component, DigitalOcean Spaces bucket compromise, and persistence mechanisms
- [GitHub Advisory - CVE-2026-18072 (ARVE Backdoor)](https://github.com/advisories/GHSA-45wh-rxq4-jqc6) — related supply chain attack attributed to the same threat actor by Wordfence

---
*Report generated by Actioner*
