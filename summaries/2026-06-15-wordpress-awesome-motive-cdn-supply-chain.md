# Technical Analysis Report: Awesome Motive CDN Supply Chain Attack (2026-06-15)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-15
Version: 1.0 DRAFT

## Executive Summary

On June 12, 2026, attackers compromised the CDN infrastructure serving JavaScript for three popular WordPress plugins operated by Awesome Motive -- OptinMonster (1M+ active installs), TrustPulse, and PushEngage. Malicious JavaScript was injected into the legitimate CDN-hosted SDK files, creating a supply chain attack that exposed an estimated 1.2 million WordPress installations. The injected code targeted logged-in WordPress administrators exclusively: it harvested authentication tokens, created backdoor admin accounts (`developer_api1`), installed a self-hiding PHP backdoor plugin with web shell and code execution capabilities, and exfiltrated credentials to `tidio[.]cc` -- a typosquatting lookalike of the legitimate `tidio[.]com` chat platform. The C2 domain was registered on April 28, 2026, indicating at least six weeks of premeditation. OptinMonster and TrustPulse CDN paths were cleaned within 25 minutes of detection on June 12; PushEngage continued serving malicious code until June 14. The root cause -- whether it was a compromise of Awesome Motive's servers, their CDN account, or their CDN provider (BunnyNet) -- remains unknown. Additional Awesome Motive plugins including WPForms (~6M installs), MonsterInsights (~2M), and All in One SEO (~3M) remain under investigation.

## Background: Awesome Motive WordPress Plugin Ecosystem

Awesome Motive is one of the largest WordPress plugin developers, operating a portfolio of plugins with a combined installation base exceeding 15 million active WordPress sites. Their plugins -- OptinMonster (lead generation), TrustPulse (social proof), PushEngage (push notifications), WPForms (forms), MonsterInsights (analytics), and All in One SEO -- are delivered via external CDN-hosted JavaScript that loads on every page view of customer sites. This architecture means a single compromised CDN file propagates instantly to all downstream sites without requiring a plugin update, making the CDN infrastructure a high-value supply chain target. This attack follows the same operational pattern as the Polyfill supply chain attack that Sansec discovered in 2024: tamper with a single upstream file and the malware reaches thousands of downstream sites without any action from site operators.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-28 | C2 domain `tidio[.]cc` registered; TLS certificate issued |
| 2026-06-12 22:17 | First confirmed malware detection in OptinMonster and TrustPulse CDN files |
| 2026-06-12 22:42 | Last confirmed malware presence in OptinMonster and TrustPulse CDN files |
| 2026-06-13 19:02 | OptinMonster and TrustPulse CDN paths confirmed clean |
| 2026-06-13 19:02 | PushEngage SDK still serving injected code from certain CDN edges |
| 2026-06-14 | PushEngage malware fully remediated |
| 2026-06-15 | Investigation into WPForms, MonsterInsights, All in One SEO ongoing |

## Root Cause: CDN Infrastructure Compromise

The malicious code did not reside on any victim's server. It was injected into JavaScript files served by Awesome Motive's CDN infrastructure. The exact compromise vector remains unknown. Sansec identifies three possibilities in decreasing order of likelihood: (1) Awesome Motive's own server infrastructure was compromised; (2) their CDN account credentials were stolen; (3) the CDN provider BunnyNet was compromised (assessed as unlikely). The rapid cleanup of OptinMonster and TrustPulse paths (within 25 minutes) while PushEngage continued serving malicious code suggests that Awesome Motive became aware of the breach quickly but remediation was incomplete across all properties.

## Technical Analysis of the Malicious Payload

### 1. CDN-Hosted JavaScript Injection (Stage 1 -- Delivery)

The attacker injected malicious JavaScript into the following CDN-hosted files that are loaded on every page of sites using these plugins:

**Compromised CDN Endpoints:**
- `a[.]omappapi[.]com/app/js/api.min.js` (OptinMonster)
- `a[.]opmnstr[.]com/app/js/api.min.js` (OptinMonster)
- `a[.]optnmstr[.]com/app/js/api.min.js` (OptinMonster)
- `a[.]trstplse[.]com/app/js/api.min.js` (TrustPulse)
- `clientcdn[.]pushengage[.]com/sdks/pushengage-web-sdk.js` (PushEngage)

### 2. Environment Fingerprinting and Admin Targeting (Stage 2 -- Reconnaissance)

The injected JavaScript implements aggressive environment checks before executing:

**Anti-Analysis Gating:**
- Exits immediately on `navigator.webdriver` detection (headless browsers)
- Exits on zero-size window detection (automated tools)
- Implements a 24-hour throttle stored in `localStorage['_pe_ts']` to prevent repeated execution

**Admin Targeting Logic:**
The payload only executes if it detects a logged-in WordPress administrator through three detection methods:
1. Presence of `wp-admin` in the current URL path
2. Detection of the WordPress admin toolbar in the DOM
3. Detection of the `wordpress_logged_in_` cookie

**WordPress Reconnaissance:**
Once admin status is confirmed, the payload:
- Fingerprints the WordPress version
- Locates the WordPress root and admin path
- Harvests REST API nonces from `wpApiSettings.nonce`
- Falls back to fetching nonces from `admin-ajax.php?action=rest-nonce`
- Scrapes nonces from the `user-new.php` admin page as a last resort

### 3. Backdoor Admin Account Creation (Stage 3 -- Persistence)

The malware creates rogue administrator accounts using four sequential fallback methods:

1. **User registration form** -- submits to `user-new.php`
2. **Admin AJAX endpoint** -- posts to `admin-ajax.php`
3. **REST API** -- creates user via `wp/v2/users` endpoint
4. **Hidden iframe** -- injects a hidden iframe with an auto-submitting form

**Created Accounts:**
- Fixed operator account: `developer_api1` with email `customer1usx[at]gmail[.]com`
- Randomized accounts: pattern `dev_xxxxxx` with email `dev_xxxxxx[at]gmail[.]com`

The malware recognizes "user already exists" error responses in approximately twenty languages, allowing it to gracefully handle cases where the backdoor account was already created on a previous execution.

### 4. Data Exfiltration (Stage 4 -- Exfiltration)

Harvested credentials and site metadata are exfiltrated using the following protocol:

**Data Payload Contents:**
- New admin username and password
- Site origin URL
- Logout URL
- Admin path
- Account creation method used
- Timing data
- WordPress version

**Encryption/Encoding:**
1. XOR encryption with key `jX9kM2nP4qR6sT8v`
2. Base64 encoding
3. Transmission to `tidio[.]cc/cdn-cgi/*` endpoints

**Delivery Fallback Chain (cascading):**
1. `navigator.sendBeacon()` (primary)
2. `fetch()` with `no-cors` mode
3. `XMLHttpRequest`
4. `new Image().src` pixel beacon (last resort)

### 5. C2 Infrastructure

**Primary C2 Domain:** `tidio[.]cc`
- **IP Address:** `84[.]201[.]6[.]54`
- **Hosting:** Ultahost (AS214036)
- **Registration Date:** 2026-04-28
- **Impersonates:** `tidio[.]com` (legitimate chat platform)

**C2 API Endpoints:**

| Endpoint | Function | Plugin Variant |
|----------|----------|----------------|
| `/cdn-cgi/p` | Credential exfiltration | OptinMonster/TrustPulse |
| `/cdn-cgi/b` | Credential exfiltration (alt) | OptinMonster/TrustPulse |
| `/cdn-cgi/l` | Payload/plugin generation | OptinMonster/TrustPulse |
| `/cdn-cgi/pe-p` | Credential exfiltration | PushEngage |
| `/cdn-cgi/pe-b` | Credential exfiltration (alt) | PushEngage |
| `/cdn-cgi/pe-l` | Payload/plugin generation | PushEngage |

The `/cdn-cgi/` path prefix mimics Cloudflare's internal routing convention, adding a layer of plausibility to the C2 traffic.

### 6. Hidden Backdoor Plugin Installation (Stage 5 -- Persistent Access)

After account creation and exfiltration, the malware requests a dynamically generated backdoor plugin from the C2:

**Plugin Generation:**
- Request: `tidio[.]cc/cdn-cgi/{pe-,}l?t=gen&u=developer_api1`
- Response: Base64-encoded blob
- Decryption: XOR key `jX9kM2nP4qR6sT8v`
- Output: Plugin ID, slug, and installable ZIP archive
- Each request generates a fresh ZIP with different file hashes but byte-identical logic

**Known Plugin Disguises:**
| Slug | Display Name | Version |
|------|-------------|---------|
| `content-delivery-helper` | Content Delivery Helper | 2.7.1 |
| `database-optimizer` | Database Optimizer | 2.9.4 |

**Backdoor Capabilities (Two Unauthenticated Entry Points):**

1. **Web Shell** (`?developer_api1_fm`):
   - Executes arbitrary system commands via `system($_POST['cmd'])`
   - Accepts file uploads
   - Branded as "WPM File Manager & Shell"

2. **PHP Eval Endpoint** (POST parameter `developer_api1_eval`):
   - Executes arbitrary PHP via `eval(base64_decode(...))`
   - Accepts attacker-supplied base64-encoded PHP code

### 7. Anti-Forensics / Evasion Techniques

The backdoor plugin actively hides from multiple WordPress discovery mechanisms:

- **Admin user list** -- the rogue accounts are hidden from the admin user management screen
- **Plugin admin interface** -- the backdoor plugin is hidden from the Plugins admin page
- **REST API** -- hidden from the `/wp/v2/plugins` REST endpoint
- **Update checks** -- excluded from WordPress update mechanisms
- **Recently active tracking** -- removed from the "Recently Active" plugin list

The operator rotates plugin slugs and display names while keeping the functional PHP logic byte-identical across renames. Fresh ZIP files are generated per request, meaning file hashes change constantly while functionality remains identical, defeating hash-based detection.

Server-side scanning of the filesystem is the most reliable detection method since the payload only ever ran for logged-in administrators, making client-side observation difficult.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Compromised Asset | Description |
|---------------------|-------------------|-------------|
| OptinMonster | `a[.]omappapi[.]com/app/js/api.min.js` | CDN-hosted JS with injected malicious payload |
| OptinMonster | `a[.]opmnstr[.]com/app/js/api.min.js` | CDN-hosted JS with injected malicious payload |
| OptinMonster | `a[.]optnmstr[.]com/app/js/api.min.js` | CDN-hosted JS with injected malicious payload |
| TrustPulse | `a[.]trstplse[.]com/app/js/api.min.js` | CDN-hosted JS with injected malicious payload |
| PushEngage | `clientcdn[.]pushengage[.]com/sdks/pushengage-web-sdk.js` | CDN-hosted JS with injected malicious payload |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| WordPress | `wp-content/plugins/content-delivery-helper/` | Hidden backdoor plugin (v2.7.1) |
| WordPress | `wp-content/plugins/database-optimizer/` | Hidden backdoor plugin (v2.9.4) |

Note: File hashes are not available because the C2 generates fresh ZIPs per request with changing hashes but identical logic.

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `tidio[.]cc` | Primary C2 domain (typosquat of tidio[.]com) |
| IP | `84[.]201[.]6[.]54` | C2 server IP (Ultahost AS214036) |
| URL Pattern | `hxxps://tidio[.]cc/cdn-cgi/p` | Credential exfiltration (OptinMonster/TrustPulse) |
| URL Pattern | `hxxps://tidio[.]cc/cdn-cgi/b` | Credential exfiltration alt (OptinMonster/TrustPulse) |
| URL Pattern | `hxxps://tidio[.]cc/cdn-cgi/l` | Plugin payload generation (OptinMonster/TrustPulse) |
| URL Pattern | `hxxps://tidio[.]cc/cdn-cgi/pe-p` | Credential exfiltration (PushEngage) |
| URL Pattern | `hxxps://tidio[.]cc/cdn-cgi/pe-b` | Credential exfiltration alt (PushEngage) |
| URL Pattern | `hxxps://tidio[.]cc/cdn-cgi/pe-l` | Plugin payload generation (PushEngage) |
| XOR Key | `jX9kM2nP4qR6sT8v` | Encryption key for exfiltration and plugin decryption |

### Behavioral

| Indicator | Description |
|-----------|-------------|
| WordPress user `developer_api1` | Fixed operator backdoor account |
| Email `customer1usx[at]gmail[.]com` | Email associated with fixed backdoor account |
| WordPress users matching `dev_xxxxxx` | Randomized backdoor accounts |
| `localStorage['_pe_ts']` | 24-hour execution throttle in browser |
| Query parameter `developer_api1_fm` | Web shell entry point |
| POST parameter `developer_api1_eval` | PHP eval entry point |
| String "WPM File Manager & Shell" | Web shell branding in backdoor plugin |
| `system($_POST['cmd'])` | Shell command execution pattern |
| `eval(base64_decode(...))` | PHP code execution pattern |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious JS injected into CDN-hosted plugin assets |
| T1583.001 | Acquire Infrastructure: Domains | `tidio[.]cc` registered as typosquat of `tidio[.]com` |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication over HTTPS to `/cdn-cgi/*` paths |
| T1567 | Exfiltration Over Web Service | Credentials XOR-encrypted and exfiltrated via sendBeacon/fetch/XHR/Image |
| T1136.001 | Create Account: Local Account | Rogue admin accounts `developer_api1` and `dev_xxxxxx` created |
| T1505.003 | Server Software Component: Web Shell | "WPM File Manager & Shell" with arbitrary command execution |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `system($_POST['cmd'])` for OS command execution |
| T1059 | Command and Scripting Interpreter | `eval(base64_decode(...))` for arbitrary PHP execution via backdoor plugin |
| T1564 | Hide Artifacts | Backdoor plugin hidden from admin UI, REST API, and update checks |
| T1556 | Modify Authentication Process | Authentication token harvesting from REST API nonces |
| T1027 | Obfuscated Files or Information | XOR encryption of exfiltrated data; polymorphic ZIP generation |

## Impact Assessment

**Breadth:** Over 1.2 million confirmed WordPress installations affected through OptinMonster, TrustPulse, and PushEngage. An additional 11+ million sites running WPForms, MonsterInsights, and All in One SEO are potentially at risk pending investigation.

**Depth:** Any WordPress site that had an administrator browse the site during the compromise window (June 12 22:17 - June 14, 2026) should assume full administrative compromise. The attacker gained: (1) admin-level access via rogue accounts, (2) unauthenticated remote code execution via the web shell, and (3) arbitrary file upload capabilities.

**Stealth:** The attack was highly targeted (admin-only execution), used a legitimate-looking typosquat domain, mimicked Cloudflare CDN paths, and deployed a self-hiding plugin that evaded the WordPress admin interface, REST API, and update system. The polymorphic plugin ZIP generation defeated hash-based detection.

**Exposure Window:** The confirmed active window is approximately 40 hours (June 12 22:17 to June 14), though the C2 domain was registered on April 28 -- the actual exploitation window may be longer if earlier injection attempts occurred undetected.

## Detection & Remediation

### Immediate Detection

**Check for rogue admin accounts (run via WP-CLI or direct database query):**
```bash
# WP-CLI
wp user list --role=administrator --fields=ID,user_login,user_email

# Direct MySQL query
SELECT ID, user_login, user_email, user_registered FROM wp_users
WHERE user_login LIKE 'developer_api1' OR user_login LIKE 'dev_%'
OR user_email LIKE 'customer1usx@gmail.com' OR user_email LIKE 'dev_%@gmail.com';
```

**Check filesystem for backdoor plugins (NOT the admin dashboard -- the plugin hides itself):**
```bash
# Search for backdoor plugin directories
ls -la wp-content/plugins/content-delivery-helper/ 2>/dev/null
ls -la wp-content/plugins/database-optimizer/ 2>/dev/null

# Search for web shell strings in plugin files
grep -rl "WPM File Manager" wp-content/plugins/
grep -rl "developer_api1_fm" wp-content/plugins/
grep -rl "developer_api1_eval" wp-content/plugins/
```

**Check web server access logs for C2 communication or backdoor access:**
```bash
# Outbound C2 traffic (if logged via proxy)
grep "tidio.cc" /var/log/nginx/access.log /var/log/apache2/access.log

# Backdoor access attempts
grep -E "developer_api1_(fm|eval)" /var/log/nginx/access.log /var/log/apache2/access.log
grep -E "(content-delivery-helper|database-optimizer)" /var/log/nginx/access.log /var/log/apache2/access.log
```

### Remediation

1. **Identify and remove rogue accounts:** Delete `developer_api1` and any `dev_xxxxxx` accounts from the WordPress user database
2. **Remove backdoor plugins from the filesystem:** Delete `wp-content/plugins/content-delivery-helper/` and `wp-content/plugins/database-optimizer/` directories directly -- do NOT rely on the admin dashboard (the plugin hides from the UI)
3. **Rotate all credentials:** Change all administrator passwords, regenerate WordPress salts in `wp-config.php`, rotate all API keys and secrets
4. **Assume full compromise:** If any IOCs are found, assume the attacker achieved unauthenticated code execution and audit all site files, database records, and server configuration for additional modifications
5. **Update plugins:** Ensure all Awesome Motive plugins are updated to the latest versions served from cleaned CDN paths
6. **Block C2 infrastructure:** Block `tidio[.]cc` and `84[.]201[.]6[.]54` at the network perimeter

### Long-Term Hardening

- Implement Subresource Integrity (SRI) hashes on all externally loaded JavaScript to detect CDN tampering
- Deploy file integrity monitoring on `wp-content/plugins/` to detect unauthorized plugin installations
- Implement Content Security Policy (CSP) headers to restrict which domains can execute JavaScript
- Monitor for new WordPress admin account creation through audit logging
- Consider self-hosting critical plugin assets rather than relying on third-party CDNs
- Run server-side malware scanning (e.g., Sansec eComscan) regularly, as client-side detection is unreliable when payloads target only admin sessions

## Detection Rules

The following rules target the distinctive artifacts of this supply chain attack: the `tidio[.]cc` C2 domain, the `/cdn-cgi/*` exfiltration paths, the `developer_api1` backdoor entry points, the XOR key, and the hidden plugin signatures. All IOC-anchored rules are high-confidence for this specific campaign but will not detect operator infrastructure rotation; the YARA behavioral rules provide broader coverage at the cost of potential false positives on unrelated WordPress malware.

<!-- Validation audit:
- All Sigma rules: sigma check passed (0 errors, 0 issues), sigma convert --without-pipeline -t splunk exit 0, sigma convert --without-pipeline -t log_scale exit 0
- All YARA rules: yarac exit 0
- All Suricata rules: suricata -T -S exit 0
- Snort rules: snort not available in environment, structural check only
- Logsource encoding: detection values use real (non-defanged) IOCs per logsource-encoding.md guidance
- No tactic-only tags used in Sigma rules
-->

### Sigma: C2 Exfiltration to tidio.cc (Proxy Logs)

Detects outbound proxy traffic to the `tidio[.]cc` C2 domain on the specific `/cdn-cgi/*` exfiltration paths.

**Compile:** sigma check pass, splunk pass, log_scale pass | **Confidence:** medium (IOC-anchored, but `/cdn-cgi/` paths overlap with legitimate Cloudflare internal routes if domain matching fails)

```yaml
title: Awesome Motive CDN Supply Chain - C2 Exfiltration to tidio.cc
id: 8e3f1a7b-4c2d-4e9f-b6a1-3d5c8f0e2a7b
status: experimental
description: >
    Detects outbound web proxy traffic to the tidio.cc C2 domain used in the
    Awesome Motive CDN supply chain attack. The attacker registered this domain
    to mimic the legitimate tidio.com and used /cdn-cgi/* paths for exfiltration
    and payload generation.
references:
    - https://sansec.io/research/optinmonster-supply-chain-attack
    - https://securityaffairs.com/193616/malware/supply-chain-attack-hits-popular-wordpress-plugins-through-awesome-motive-cdn.html
author: Actioner
date: 2026-06-15
tags:
    - attack.t1071.001
    - attack.t1567
logsource:
    category: proxy
detection:
    selection_domain:
        c-uri|contains: 'tidio.cc'
    selection_path:
        c-uri|contains:
            - '/cdn-cgi/p'
            - '/cdn-cgi/b'
            - '/cdn-cgi/l'
            - '/cdn-cgi/pe-p'
            - '/cdn-cgi/pe-b'
            - '/cdn-cgi/pe-l'
    condition: selection_domain and selection_path
falsepositives:
    - None expected; tidio.cc is a known malicious lookalike domain
level: high
```

### Sigma: Backdoor Plugin Access via Web Server Logs

Detects HTTP requests to the unauthenticated backdoor entry points (`developer_api1_fm`, `developer_api1_eval`) or the hidden plugin directory paths.

**Compile:** sigma check pass, splunk pass, log_scale pass | **Confidence:** medium (parameter names are highly distinctive but could appear in unrelated custom code)

```yaml
title: Awesome Motive CDN Supply Chain - Backdoor Plugin Access via Web Server Logs
id: a1b2c3d4-5e6f-7a8b-9c0d-e1f2a3b4c5d6
status: experimental
description: >
    Detects HTTP requests to the unauthenticated backdoor entry points installed
    by the Awesome Motive CDN supply chain attack. The hidden plugins expose a
    file manager shell via developer_api1_fm and a PHP eval endpoint via
    developer_api1_eval query parameters.
references:
    - https://sansec.io/research/optinmonster-supply-chain-attack
    - https://securityaffairs.com/193616/malware/supply-chain-attack-hits-popular-wordpress-plugins-through-awesome-motive-cdn.html
author: Actioner
date: 2026-06-15
tags:
    - attack.t1505.003
    - attack.t1059.004
logsource:
    category: webserver
detection:
    selection_shell:
        cs-uri-query|contains: 'developer_api1_fm'
    selection_eval:
        cs-uri-query|contains: 'developer_api1_eval'
    selection_plugin_path:
        cs-uri-stem|contains:
            - '/content-delivery-helper/'
            - '/database-optimizer/'
    condition: selection_shell or selection_eval or selection_plugin_path
falsepositives:
    - Legitimate plugins named content-delivery-helper or database-optimizer are not known to exist
level: high
```

### Sigma: DNS Query to C2 Domain tidio.cc

Detects DNS resolution of the `tidio[.]cc` C2 domain.

**Compile:** sigma check pass, splunk pass, log_scale pass | **Confidence:** medium (domain is campaign-specific but will stop firing once C2 infrastructure rotates)

```yaml
title: Awesome Motive CDN Supply Chain - DNS Query to C2 Domain tidio.cc
id: f7e8d9c0-1a2b-3c4d-5e6f-7a8b9c0d1e2f
status: experimental
description: >
    Detects DNS resolution requests for tidio.cc, the C2 domain used in the
    Awesome Motive CDN supply chain attack. This domain mimics the legitimate
    tidio.com chat service and was registered on 2026-04-28 specifically for
    this campaign.
references:
    - https://sansec.io/research/optinmonster-supply-chain-attack
    - https://securityaffairs.com/193616/malware/supply-chain-attack-hits-popular-wordpress-plugins-through-awesome-motive-cdn.html
author: Actioner
date: 2026-06-15
tags:
    - attack.t1071.001
    - attack.t1583.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'tidio.cc'
    condition: selection
falsepositives:
    - None expected; tidio.cc is a known malicious domain registered for this attack
level: high
```

### YARA: Backdoor Plugin PHP Detection

Detects the hidden PHP backdoor plugin by matching on the web shell branding, backdoor parameter names, and plugin slug combined with operator account identifiers.

**Compile:** yarac pass | **Confidence:** medium (string combinations are highly specific to this campaign)

```yara
rule SupplyChain_AwesomeMotive_Backdoor_Plugin_PHP
{
    meta:
        description = "Detects the hidden backdoor plugin installed by the Awesome Motive CDN supply chain attack. Matches on distinctive strings from the web shell and eval entry points."
        author = "Actioner"
        date = "2026-06-15"
        reference = "https://sansec.io/research/optinmonster-supply-chain-attack"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $shell_brand = "WPM File Manager & Shell" ascii
        $param_fm = "developer_api1_fm" ascii
        $param_eval = "developer_api1_eval" ascii
        $account = "developer_api1" ascii
        $email = "customer1usx@gmail.com" ascii
        $slug1 = "content-delivery-helper" ascii
        $slug2 = "database-optimizer" ascii

    condition:
        filesize < 500KB and
        (
            $shell_brand or
            ($param_fm and $param_eval) or
            (any of ($slug*) and ($account or $email))
        )
}
```

### YARA: Malicious JavaScript Detection

Detects the injected JavaScript payload by matching on the XOR exfiltration key, C2 domain combined with CDN-cgi paths, or the C2 domain with WordPress cookie detection.

**Compile:** yarac pass | **Confidence:** medium (XOR key `jX9kM2nP4qR6sT8v` is the strongest single indicator; C2 domain + path combinations are campaign-specific)

```yara
rule SupplyChain_AwesomeMotive_Malicious_JS
{
    meta:
        description = "Detects malicious JavaScript injected via Awesome Motive CDN supply chain attack. Keys on XOR exfiltration key, C2 domain, and admin detection logic."
        author = "Actioner"
        date = "2026-06-15"
        reference = "https://sansec.io/research/optinmonster-supply-chain-attack"
        tlp = "WHITE"
        severity = "high"

    strings:
        $xor_key = "jX9kM2nP4qR6sT8v" ascii
        $c2_domain = "tidio.cc" ascii
        $c2_path1 = "/cdn-cgi/p" ascii
        $c2_path2 = "/cdn-cgi/pe-p" ascii
        $c2_path3 = "/cdn-cgi/l" ascii
        $c2_path4 = "/cdn-cgi/pe-l" ascii
        $wp_cookie = "wordpress_logged_in_" ascii
        $localstorage = "_pe_ts" ascii
        $rest_nonce = "wpApiSettings" ascii

    condition:
        filesize < 2MB and
        (
            $xor_key or
            ($c2_domain and any of ($c2_path*)) or
            ($c2_domain and $wp_cookie) or
            ($localstorage and $rest_nonce and $c2_domain)
        )
}
```

### Suricata: Network Detection Rules

Four rules covering DNS resolution, HTTP C2 exfiltration, and backdoor web shell access.

**Compile:** suricata -T pass (all 4 rules) | **Confidence:** medium (IOC-anchored to `tidio[.]cc` and `developer_api1` strings)

```
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Awesome Motive Supply Chain C2 Domain tidio.cc"; flow:to_server; dns.query; content:"tidio.cc"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/optinmonster-supply-chain-attack; metadata:author Actioner, created_at 2026-06-15; sid:2100101; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Exfiltration to Awesome Motive C2 tidio.cc cdn-cgi Path"; flow:established,to_server; http.host; content:"tidio.cc"; fast_pattern; http.uri; content:"/cdn-cgi/"; classtype:trojan-activity; reference:url,sansec.io/research/optinmonster-supply-chain-attack; metadata:author Actioner, created_at 2026-06-15; sid:2100102; rev:1;)

alert http $HOME_NET any -> $HOME_NET any (msg:"Actioner - WordPress Backdoor Plugin Shell Access developer_api1_fm"; flow:established,to_server; http.uri; content:"developer_api1_fm"; fast_pattern; classtype:web-application-attack; reference:url,sansec.io/research/optinmonster-supply-chain-attack; metadata:author Actioner, created_at 2026-06-15; sid:2100103; rev:1;)

alert http $HOME_NET any -> $HOME_NET any (msg:"Actioner - WordPress Backdoor Plugin Eval Endpoint developer_api1_eval"; flow:established,to_server; http.uri; content:"developer_api1_eval"; fast_pattern; classtype:web-application-attack; reference:url,sansec.io/research/optinmonster-supply-chain-attack; metadata:author Actioner, created_at 2026-06-15; sid:2100104; rev:1;)
```

### Snort 3: Network Detection Rules

Two rules covering HTTP C2 communication and backdoor web shell access.

**Compile:** :warning: uncompiled (structural check only -- Snort 3 not available in environment) | **Confidence:** medium

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP C2 to Awesome Motive Supply Chain Domain tidio.cc"; flow:established, to_server; http_header; content:"tidio.cc", fast_pattern; http_uri; content:"/cdn-cgi/"; classtype:trojan-activity; reference:url,sansec.io/research/optinmonster-supply-chain-attack; metadata:author Actioner, created 2026-06-15; sid:2100201; rev:1;)

alert http $HOME_NET any -> $HOME_NET any (msg:"Actioner - WordPress Backdoor Shell Access developer_api1_fm"; flow:established, to_server; http_uri; content:"developer_api1_fm", fast_pattern; classtype:web-application-attack; reference:url,sansec.io/research/optinmonster-supply-chain-attack; metadata:author Actioner, created 2026-06-15; sid:2100202; rev:1;)
```

## Lessons Learned

This attack demonstrates that CDN-hosted JavaScript remains one of the most dangerous supply chain attack surfaces. A single compromised CDN file can instantly propagate malicious code to millions of downstream sites without requiring a plugin update, bypassing all local file integrity checks. The attack's targeting logic (admin-only execution, anti-bot detection, 24-hour throttling) represents an evolution in supply chain malware sophistication, making client-side detection extremely difficult. The self-hiding backdoor plugin that evades the WordPress admin UI, REST API, and update system highlights that filesystem-level scanning is essential -- dashboard-based security tools are insufficient against this class of threat.

The attack underscores the need for Subresource Integrity (SRI) adoption on externally loaded scripts, server-side file integrity monitoring, and robust admin account audit logging. WordPress site operators loading any JavaScript from third-party CDNs should treat those CDN endpoints as part of their security perimeter.

## Sources

- [Sansec - OptinMonster supply chain attack hits 1.2 million sites](https://sansec.io/research/optinmonster-supply-chain-attack) -- primary technical research with full IOCs, timeline, C2 infrastructure details, and backdoor plugin analysis
- [Security Affairs - Supply chain attack hits popular WordPress plugins through Awesome Motive CDN](https://securityaffairs.com/193616/malware/supply-chain-attack-hits-popular-wordpress-plugins-through-awesome-motive-cdn.html) -- news coverage with additional context on scope and affected plugin portfolio
- [Essential Code - The WordPress Plugin Supply Chain Attack](https://www.essentialcode.eu/blog/wordpress-plugin-supply-chain-attack) -- context on broader WordPress supply chain attack trends and the related April 2026 Essential Plugin portfolio compromise

---
*Report generated by Actioner*
