# Technical Analysis Report: Awesome Motive CDN Supply Chain Attack (2026-06-16)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-16
Version: 1.0 (DRAFT)

---

## Executive Summary

On June 12, 2026, attackers compromised the Content Delivery Network (CDN) infrastructure used by Awesome Motive -- a major WordPress plugin vendor -- to inject malicious JavaScript into three widely deployed plugins: **OptinMonster** (1M+ active installations), **TrustPulse**, and **PushEngage** (9,000+ installations). The combined exposure spans approximately **1.2 million WordPress sites**.

The injected code targeted logged-in WordPress administrators, silently creating backdoor admin accounts, installing self-hiding PHP backdoor plugins with web shell capabilities, and exfiltrating the new credentials to the attacker-controlled domain `tidio[.]cc` (a typosquat of the legitimate tidio[.]com). The attack chain leveraged a pre-existing vulnerability in the UpdraftPlus plugin (CVE-2026-10795, CVSS 8.1) to gain initial access to an Awesome Motive marketing server, where a CDN API key was recovered and used to tamper with SDK files served through BunnyNet CDN.

The campaign was discovered and disclosed by security firm [Sansec](https://sansec.io/research/optinmonster-supply-chain-attack) on June 13, 2026. The malicious OptinMonster/TrustPulse payloads were served for approximately 25 minutes; PushEngage remained compromised for roughly 44 hours longer due to CDN edge caching.

---

## Background: WordPress Plugin CDN Infrastructure

Awesome Motive develops and distributes some of the most popular WordPress plugins in the ecosystem. Rather than bundling all functionality into plugin PHP files, these plugins load external JavaScript SDKs from Awesome Motive's CDN at runtime. This architecture means that a compromise of the CDN layer -- without touching individual WordPress installations -- can inject malicious code into every site loading those scripts.

**Affected CDN-served assets:**

| Plugin | CDN Host | File Path |
|--------|----------|-----------|
| OptinMonster | `a.omappapi[.]com` | `/app/js/api.min.js` |
| OptinMonster | `a.opmnstr[.]com` | `/app/js/api.min.js` |
| OptinMonster | `a.optnmstr[.]com` | `/app/js/api.min.js` |
| TrustPulse | `a.trstplse[.]com` | `/app/js/api.min.js` |
| PushEngage | `clientcdn.pushengage[.]com` | `/sdks/pushengage-web-sdk.js` |

The CDN infrastructure is served through **BunnyNet**, a third-party CDN provider. The attacker did not compromise BunnyNet itself but instead obtained a CDN API key that allowed direct file manipulation on the CDN without needing access to origin servers.

---

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| **2026-04-28** | Attacker registers domain `tidio[.]cc`; TLS certificate issued |
| **2026-06-12 ~22:17** | Malicious JavaScript first appears in OptinMonster and TrustPulse CDN-served files |
| **2026-06-12 ~22:42** | OptinMonster and TrustPulse CDN files cleaned (~25-minute window) |
| **2026-06-13 13:28** | [Sansec publishes advisory](https://sansec.io/research/optinmonster-supply-chain-attack) |
| **2026-06-13 19:02** | PushEngage still serving injected code from certain CDN edge nodes |
| **2026-06-14 08:44** | PushEngage CDN files fully cleaned across all edges |
| **2026-06-15 00:25** | Awesome Motive publishes incident notices for all three plugins |
| **2026-06-16** | C2 domain `tidio[.]cc` remains active, continuing to generate fresh backdoor payloads |

**Key observation:** The OptinMonster/TrustPulse exposure window was narrow (25 minutes), but PushEngage remained compromised for approximately 34-44 hours due to CDN edge propagation delays. The C2 infrastructure was pre-staged at least 45 days before the attack (domain registered April 28).

---

## Root Cause: UpdraftPlus Authentication Bypass (CVE-2026-10795)

The initial access vector was **CVE-2026-10795**, an unauthenticated authentication bypass in the UpdraftPlus WordPress plugin (versions <= 1.26.4, CVSS 8.1). The vulnerability resides in the `UpdraftPlus_Remote_Communications_V2::wp_loaded` function, where signature verification can be bypassed causing decryption to collapse to a predictable all-zero encryption key.

**Attack path:**

1. Attacker exploited CVE-2026-10795 on Awesome Motive's marketing WordPress site
2. Gained administrative access to the marketing server
3. Located a stored CDN API key for the BunnyNet CDN
4. Used the CDN API key to tamper with SDK JavaScript files served to all customers

This represents a **multi-hop supply chain attack**: vulnerability in a third-party plugin (UpdraftPlus) --> compromise of vendor infrastructure (Awesome Motive marketing server) --> CDN credential theft --> malicious payload injection to 1.2M downstream sites.

---

## Technical Analysis of the Malicious Payload

The injected JavaScript payload operates as a sophisticated, multi-stage attack with extensive evasion, persistence, and exfiltration capabilities.

### Stage 1: Environment Validation and Evasion

Before executing, the payload performs multiple anti-analysis checks:

- **Headless browser detection:** Exits if `navigator.webdriver` is set
- **Window size check:** Exits on zero-dimension browser windows (common in automated analysis)
- **WordPress admin verification:** Confirms the visitor is a logged-in administrator by checking:
  - Presence of `wp-admin` in the URL path
  - Presence of the WordPress admin toolbar in the DOM
  - Existence of the `wordpress_logged_in_` cookie
- **Execution throttling:** Uses `localStorage['_pe_ts']` to enforce a 24-hour cooldown, preventing repeated execution on the same browser

### Stage 2: Reconnaissance

Once validated as an admin session, the payload:

- Locates the WordPress installation root directory
- Fingerprints the WordPress version
- Harvests authentication tokens (nonces) from:
  - WordPress REST API settings (`wpApiSettings`)
  - Admin AJAX endpoint configuration

### Stage 3: Backdoor Administrator Account Creation

The malware creates rogue administrator accounts using **four sequential fallback methods**, proceeding to the next if the previous fails:

1. **`user-new.php` form submission** -- Standard WordPress user creation form
2. **`admin-ajax.php` AJAX request** -- WordPress AJAX handler
3. **REST API `wp/v2/users` endpoint** -- WordPress REST API
4. **Hidden iframe form submission** -- Injected invisible iframe as final fallback

**Account details:**
- **Primary fixed account:** Username `developer_api1`, email `customer1usx@gmail[.]com`
- **Randomized accounts:** Pattern `dev_xxxxxx` with corresponding `dev_xxxxxx@gmail[.]com`

The malware includes error message recognition in approximately 20 languages to detect and handle failed creation attempts.

### Stage 4: Hidden Backdoor Plugin Installation

After establishing admin accounts, the payload silently installs a PHP backdoor plugin disguised as a legitimate utility:

**Observed disguises:**

| Plugin Slug | Display Name | Version |
|-------------|-------------|---------|
| `content-delivery-helper` | Content Delivery Helper | 2.7.1 |
| `database-optimizer` | Database Optimizer | 2.9.4 |

**Stealth mechanisms -- the plugin hides itself from:**
- WordPress user list (dashboard)
- Plugin list (admin dashboard)
- REST API `/wp/v2/plugins` endpoint
- Update checks
- "Recently Active" list

**Backdoor capabilities:**

| Access Method | Trigger | Capability |
|---------------|---------|------------|
| `?developer_api1_fm` | GET parameter | "WPM File Manager & Shell" -- executes arbitrary system commands via `system()`, accepts file uploads |
| `POST` to `developer_api1_eval` | POST parameter | Executes arbitrary PHP code via `eval()` on base64-decoded input |

**Critical note:** The backdoor plugin ZIP is **generated fresh per request** by the C2 server, producing changing file hashes with identical functionality. This makes hash-based detection unreliable.

### Stage 5: Credential Exfiltration

Stolen credentials and site metadata are exfiltrated to `tidio[.]cc` using:

**Encryption:** XOR encryption with hardcoded key `jX9kM2nP4qR6sT8v`, followed by Base64 encoding.

**Exfiltrated data fields:**
- New administrator credentials (username + password)
- Site origin URL
- WordPress logout URL
- Admin path
- WordPress version
- Timing and method metadata

**Exfiltration endpoints on `tidio[.]cc`:**

| Path | Purpose |
|------|---------|
| `/cdn-cgi/p` | Credential exfiltration (OptinMonster/TrustPulse) |
| `/cdn-cgi/b` | Beacon exfiltration (OptinMonster/TrustPulse) |
| `/cdn-cgi/l` | Payload/plugin delivery (OptinMonster/TrustPulse) |
| `/cdn-cgi/pe-p` | Credential exfiltration (PushEngage) |
| `/cdn-cgi/pe-b` | Beacon exfiltration (PushEngage) |
| `/cdn-cgi/pe-l` | Payload/plugin delivery (PushEngage) |

**Delivery fallback chain:** The exfiltration uses four methods in sequence:
1. `navigator.sendBeacon()` (preferred -- fires even during page unload)
2. `fetch()` with `no-cors` mode
3. `XMLHttpRequest`
4. `new Image().src` beacon (pixel tracking fallback)

---

## Indicators of Compromise (IOCs)

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| Domain | `tidio[.]cc` | C2 domain (typosquat of tidio[.]com) |
| IP Address | `84[.]201[.]6[.]54` | C2 IP (Ultahost AS214036) |
| URL Path | `tidio[.]cc/cdn-cgi/p` | Credential exfiltration endpoint |
| URL Path | `tidio[.]cc/cdn-cgi/b` | Beacon exfiltration endpoint |
| URL Path | `tidio[.]cc/cdn-cgi/l` | Backdoor plugin delivery |
| URL Path | `tidio[.]cc/cdn-cgi/pe-p` | PushEngage credential exfiltration |
| URL Path | `tidio[.]cc/cdn-cgi/pe-b` | PushEngage beacon exfiltration |
| URL Path | `tidio[.]cc/cdn-cgi/pe-l` | PushEngage plugin delivery |

### Host Indicators

| Type | Value | Context |
|------|-------|---------|
| Username | `developer_api1` | Primary backdoor admin account |
| Username pattern | `dev_xxxxxx` | Randomized backdoor admin accounts |
| Email | `customer1usx@gmail[.]com` | Primary backdoor account email |
| Email pattern | `dev_xxxxxx@gmail[.]com` | Randomized account emails |
| Plugin directory | `wp-content/plugins/content-delivery-helper/` | Backdoor plugin (disguise 1) |
| Plugin directory | `wp-content/plugins/database-optimizer/` | Backdoor plugin (disguise 2) |
| URL parameter | `?developer_api1_fm` | Web shell access trigger |
| URL parameter | `developer_api1_eval` | PHP eval access trigger |
| String | `jX9kM2nP4qR6sT8v` | XOR encryption key in JS/PHP |
| String | `WPM File Manager` | Web shell UI title |
| localStorage key | `_pe_ts` | Execution throttle timestamp |

### Compromised CDN Assets (now cleaned)

| CDN Host | File |
|----------|------|
| `a.omappapi[.]com` | `/app/js/api.min.js` |
| `a.opmnstr[.]com` | `/app/js/api.min.js` |
| `a.optnmstr[.]com` | `/app/js/api.min.js` |
| `a.trstplse[.]com` | `/app/js/api.min.js` |
| `clientcdn.pushengage[.]com` | `/sdks/pushengage-web-sdk.js` |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Usage in This Attack |
|-------------|----------------|---------------------|
| **T1195.002** | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected via compromised CDN serving plugin JavaScript |
| **T1189** | Drive-by Compromise | Malicious JS executes when admin visits any page loading the poisoned CDN script |
| **T1059.007** | Command and Scripting Interpreter: JavaScript | Malicious JavaScript payload performs all client-side attack stages |
| **T1059.004** | Command and Scripting Interpreter: Unix Shell | Backdoor plugin provides `system()` command execution |
| **T1136.001** | Create Account: Local Account | Rogue administrator accounts created via multiple WordPress API methods |
| **T1078.001** | Valid Accounts: Default Accounts | Attacker uses newly created admin accounts to maintain access |
| **T1505.003** | Server Software Component: Web Shell | "WPM File Manager & Shell" backdoor with file upload and command execution |
| **T1071.001** | Application Layer Protocol: Web Protocols | C2 communication via HTTPS to tidio[.]cc |
| **T1071.004** | Application Layer Protocol: DNS | DNS resolution of C2 domain |
| **T1041** | Exfiltration Over C2 Channel | Credentials and site data sent to tidio[.]cc via sendBeacon/fetch/XHR/Image |
| **T1027** | Obfuscated Files or Information | XOR encryption + Base64 encoding of exfiltrated data |
| **T1564.001** | Hide Artifacts: Hidden Files and Directories | Backdoor plugin hides from WordPress dashboard, plugin list, and REST API |
| **T1082** | System Information Discovery | WordPress version fingerprinting and installation root discovery |
| **T1539** | Steal Web Session Cookie | Harvesting of authentication nonces and session tokens |
| **T1584.006** | Compromise Infrastructure: Web Services | Abuse of compromised CDN API key to serve malicious content |

---

## Impact Assessment

### Scope

- **1.2 million+ WordPress sites** potentially exposed
- OptinMonster alone accounts for 1M+ active installations
- PushEngage had a significantly longer exposure window (~34-44 hours vs. 25 minutes)

### Severity: CRITICAL

- **Full administrative takeover** of affected WordPress sites
- **Unauthenticated remote code execution** via the installed backdoor plugin
- **Persistent access** that survives CDN cleanup -- once the backdoor plugin is installed, the attacker no longer needs the CDN vector
- **Credential theft** of site admin credentials, enabling long-term access even if the backdoor is removed
- **Stealth design** makes detection via the WordPress dashboard impossible; direct filesystem inspection is required

### Business Impact

- Affected sites should be treated as fully compromised
- All data accessible to WordPress (database contents, user PII, payment information for e-commerce sites) should be considered potentially exposed
- The backdoor's `system()` execution capability means server-level compromise is possible, extending impact beyond WordPress

---

## Detection & Remediation

### Immediate Detection Steps

1. **Check for rogue administrator accounts:**
   - Query the WordPress database directly: `SELECT * FROM wp_users JOIN wp_usermeta ON wp_users.ID = wp_usermeta.user_id WHERE wp_usermeta.meta_key = 'wp_capabilities' AND wp_usermeta.meta_value LIKE '%administrator%';`
   - Look for usernames `developer_api1` or matching pattern `dev_xxxxxx`
   - **Do NOT rely on the WordPress dashboard** -- the backdoor plugin hides accounts from the UI

2. **Scan filesystem for backdoor plugins:**
   - Check for directories: `wp-content/plugins/content-delivery-helper/` and `wp-content/plugins/database-optimizer/`
   - Search PHP files for the XOR key: `grep -r "jX9kM2nP4qR6sT8v" wp-content/`
   - Search for the web shell identifier: `grep -r "WPM File Manager" wp-content/`
   - Search for backdoor parameters: `grep -r "developer_api1_fm\|developer_api1_eval" wp-content/`

3. **Check web server access logs:**
   - Look for requests to `tidio[.]cc` or containing `developer_api1_fm` / `developer_api1_eval`
   - Look for POST requests to `/wp-json/wp/v2/users` or `/wp-admin/user-new.php` with `developer_api1` in the body

4. **Check DNS/proxy logs:**
   - Query for resolutions of `tidio[.]cc` or connections to `84[.]201[.]6[.]54`

### Remediation Steps

1. **Remove backdoor plugins** -- delete the plugin directories entirely from the filesystem
2. **Remove rogue admin accounts** -- delete from the database directly
3. **Rotate ALL admin credentials** -- assume all admin passwords are compromised
4. **Rotate all WordPress salts and keys** in `wp-config.php`
5. **Update UpdraftPlus** to version 1.26.5+ to close CVE-2026-10795
6. **Audit server-level access** -- the `system()` capability means the attacker may have pivoted beyond WordPress
7. **Review and rotate any API keys or secrets** stored in the WordPress database or files
8. **Implement Subresource Integrity (SRI)** for external JavaScript where supported
9. **Consider a Content Security Policy (CSP)** restricting script-src to known legitimate domains

---

## Detection Rules

The following detection rules target specific, distinctive artifacts of this attack at the network (proxy/DNS), web server, and file system layers. All rules are tuned to advisory-specific indicators with minimal false positive risk. Rules were validated against their respective compilers where tooling is available.

### Sigma Rules

#### 1. Tidio.cc C2 Communication (Proxy Logs)

Detects HTTP requests to the attacker-controlled `tidio[.]cc` domain targeting the `/cdn-cgi/` exfiltration and payload delivery paths used in this campaign.

**Compile status:** PASS (sigma check + splunk + log_scale) | **Confidence:** HIGH

<!-- audit: sigma check 0 errors/0 issues; splunk convert OK; log_scale convert OK; attempt 2/3 (fixed ATT&CK tag) -->

```yaml
title: Awesome Motive Supply Chain - Tidio.cc C2 Communication
id: 8a3f1c72-5d4e-4b91-a6e0-7c2d8f9b0e13
status: experimental
description: Detects HTTP requests to the tidio.cc command-and-control domain used in the Awesome Motive CDN supply chain attack. The attacker exfiltrates credentials and retrieves backdoor payloads via paths under /cdn-cgi/.
references:
    - https://sansec.io/research/optinmonster-supply-chain-attack
    - https://securityaffairs.com/193616/malware/supply-chain-attack-hits-popular-wordpress-plugins-through-awesome-motive-cdn.html
author: Actioner
date: 2026-06-16
tags:
    - attack.exfiltration
    - attack.t1071.001
    - attack.t1041
logsource:
    category: proxy
detection:
    selection_domain:
        c-uri|contains: 'tidio.cc'
    selection_paths:
        c-uri|contains:
            - '/cdn-cgi/p'
            - '/cdn-cgi/b'
            - '/cdn-cgi/l'
            - '/cdn-cgi/pe-p'
            - '/cdn-cgi/pe-b'
            - '/cdn-cgi/pe-l'
    condition: selection_domain and selection_paths
falsepositives:
    - Legitimate traffic to tidio.cc is unlikely as the domain is attacker-controlled and distinct from tidio.com
level: high
```

#### 2. Backdoor Admin Account Creation (Web Server Logs)

Detects WordPress HTTP POST requests to user creation endpoints containing the attacker-specific username `developer_api1` or email prefix `customer1usx`, corresponding to the malware's backdoor account creation mechanism.

**Compile status:** PASS (sigma check + splunk + log_scale) | **Confidence:** HIGH

<!-- audit: sigma check 0 errors/0 issues; splunk convert OK; log_scale convert OK; attempt 2/3 (fixed ATT&CK tag); note: requires cs-body logging which may not be enabled in all web servers -->

```yaml
title: Awesome Motive Supply Chain - Backdoor Admin Account Creation
id: 2b7e9d45-8c1a-4f63-b502-3e6a7d8c9f14
status: experimental
description: Detects WordPress HTTP POST requests associated with the creation of backdoor administrator accounts by the Awesome Motive supply chain malware. The malware uses multiple fallback methods to create rogue admin users.
references:
    - https://sansec.io/research/optinmonster-supply-chain-attack
author: Actioner
date: 2026-06-16
tags:
    - attack.persistence
    - attack.t1136.001
    - attack.t1078.001
logsource:
    category: webserver
detection:
    selection_method:
        cs-method: 'POST'
    selection_user_creation:
        c-uri|contains:
            - '/wp-admin/user-new.php'
            - '/wp-admin/admin-ajax.php'
            - '/wp-json/wp/v2/users'
    selection_username:
        cs-body|contains:
            - 'developer_api1'
            - 'customer1usx'
    condition: selection_method and selection_user_creation and selection_username
falsepositives:
    - Legitimate administrator creating a user with a matching name (extremely unlikely)
level: critical
```

Caveat: Requires web server request body logging (`cs-body`), which is not enabled by default on most web servers.

#### 3. Backdoor Plugin Web Shell Access (Web Server Logs)

Detects HTTP requests containing the backdoor-specific query parameters `developer_api1_fm` (file manager/web shell) or `developer_api1_eval` (PHP eval endpoint) used by the attacker for post-exploitation access.

**Compile status:** PASS (sigma check + splunk + log_scale) | **Confidence:** HIGH

<!-- audit: sigma check 0 errors/0 issues; splunk convert OK; log_scale convert OK; attempt 1/3 -->

```yaml
title: Awesome Motive Supply Chain - Backdoor Plugin Web Shell Access
id: 4c8f2e67-1d3b-4a95-c704-5f9b0e1d2a36
status: experimental
description: Detects HTTP requests to the backdoor web shell and code execution endpoints installed by the Awesome Motive supply chain attack malware. The attacker accesses these via query parameters containing developer_api1_fm (file manager) and developer_api1_eval (PHP eval).
references:
    - https://sansec.io/research/optinmonster-supply-chain-attack
author: Actioner
date: 2026-06-16
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.execution
    - attack.t1059.004
logsource:
    category: webserver
detection:
    selection:
        c-uri|contains:
            - 'developer_api1_fm'
            - 'developer_api1_eval'
    condition: selection
falsepositives:
    - None expected; these are attacker-specific parameter names
level: critical
```

#### 4. DNS Query to Tidio.cc C2 Domain

Detects DNS resolution requests for the attacker-registered domain `tidio[.]cc`, used as the sole C2 and exfiltration endpoint in this campaign.

**Compile status:** PASS (sigma check + splunk + log_scale) | **Confidence:** HIGH

<!-- audit: sigma check 0 errors/0 issues; splunk convert OK; log_scale convert OK; attempt 2/3 (fixed ATT&CK tag) -->

```yaml
title: Awesome Motive Supply Chain - DNS Query to Tidio.cc C2 Domain
id: 6e1a3b89-2f5c-4d07-e916-8a4c7b0d3e58
status: experimental
description: Detects DNS queries resolving the attacker-controlled domain tidio.cc, used as the command-and-control server in the Awesome Motive CDN supply chain attack.
references:
    - https://sansec.io/research/optinmonster-supply-chain-attack
author: Actioner
date: 2026-06-16
tags:
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection:
        query|endswith:
            - '.tidio.cc'
        query|contains:
            - 'tidio.cc'
    condition: selection
falsepositives:
    - Legitimate tidio.cc traffic is unlikely as this is an attacker-registered domain mimicking tidio.com
level: high
```

### YARA Rules

#### 5. Backdoor Plugin File Detection

Detects the hidden PHP backdoor plugin installed by the malware, matching on the XOR encryption key, web shell parameter names, shell UI title, and the combination of known plugin slugs with backdoor account indicators.

**Compile status:** PASS (yarac) | **Confidence:** HIGH

<!-- audit: yarac compile pass; attempt 2/3 (fixed unreferenced string $beacon_method) -->

```yara
rule AwesomeMotive_SupplyChain_BackdoorPlugin
{
    meta:
        description = "Detects the hidden backdoor plugin installed by the Awesome Motive CDN supply chain attack. Matches on PHP files containing the web shell parameter names, the XOR key, and characteristic plugin metadata."
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://sansec.io/research/optinmonster-supply-chain-attack"
        severity = "critical"
        hash = "n/a - payload is generated per-request with rotating hashes"

    strings:
        $xor_key = "jX9kM2nP4qR6sT8v" ascii wide
        $shell_param = "developer_api1_fm" ascii wide
        $eval_param = "developer_api1_eval" ascii wide
        $shell_title = "WPM File Manager" ascii wide
        $plugin_slug1 = "content-delivery-helper" ascii wide
        $plugin_slug2 = "database-optimizer" ascii wide
        $backdoor_user = "developer_api1" ascii wide
        $backdoor_email = "customer1usx@gmail.com" ascii wide

    condition:
        any of ($xor_key, $shell_param, $eval_param, $shell_title) or
        (any of ($plugin_slug1, $plugin_slug2) and any of ($backdoor_user, $backdoor_email))
}
```

#### 6. Malicious JavaScript Payload Detection

Detects the injected JavaScript payload in CDN-served files by matching on combinations of the XOR encryption key with the C2 domain, multiple C2 paths, or the key combined with WordPress-specific reconnaissance strings.

**Compile status:** PASS (yarac) | **Confidence:** HIGH

<!-- audit: yarac compile pass; attempt 2/3 (fixed unreferenced string) -->

```yara
rule AwesomeMotive_SupplyChain_MaliciousJS
{
    meta:
        description = "Detects the malicious JavaScript payload injected into Awesome Motive CDN-served plugin files. Matches on the XOR encryption key, C2 domain, and characteristic exfiltration code patterns."
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://sansec.io/research/optinmonster-supply-chain-attack"
        severity = "high"

    strings:
        $xor_key = "jX9kM2nP4qR6sT8v" ascii
        $c2_domain = "tidio.cc" ascii
        $c2_path1 = "/cdn-cgi/p" ascii
        $c2_path2 = "/cdn-cgi/b" ascii
        $c2_path3 = "/cdn-cgi/l" ascii
        $c2_path4 = "/cdn-cgi/pe-p" ascii
        $c2_path5 = "/cdn-cgi/pe-b" ascii
        $c2_path6 = "/cdn-cgi/pe-l" ascii
        $cookie_check = "wordpress_logged_in_" ascii
        $localStorage_key = "_pe_ts" ascii
        $rogue_user = "developer_api1" ascii
        $beacon_method = "sendBeacon" ascii
        $exfil_email = "customer1usx" ascii

    condition:
        ($xor_key and $c2_domain) or
        ($c2_domain and 2 of ($c2_path*)) or
        ($xor_key and any of ($cookie_check, $localStorage_key, $rogue_user)) or
        ($beacon_method and $exfil_email and $c2_domain)
}
```

### Suricata Rules

#### 7-11. Network Detection Rules (Suricata/Snort)

Five Suricata rules covering DNS resolution of the C2 domain, HTTP requests to exfiltration endpoints, payload delivery paths, direct connection to the C2 IP, and XOR key presence in HTTP request bodies.

**Compile status:** UNCOMPILED (structural check only) | **Confidence:** HIGH

<!-- audit: suricata not installed; structural review pass; SID range 2026061601-2026061605; standard http/dns keywords used -->

```
# Detect DNS query to tidio.cc C2 domain
alert dns $HOME_NET any -> any any (msg:"MALWARE Awesome Motive Supply Chain - DNS Query to tidio.cc C2"; dns.query; content:"tidio.cc"; nocase; reference:url,sansec.io/research/optinmonster-supply-chain-attack; classtype:trojan-activity; sid:2026061601; rev:1;)

# Detect HTTP traffic to tidio.cc C2 exfiltration endpoint
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Awesome Motive Supply Chain - HTTP Request to tidio.cc C2 Exfil Path"; flow:established,to_server; http.host; content:"tidio.cc"; http.uri; content:"/cdn-cgi/"; reference:url,sansec.io/research/optinmonster-supply-chain-attack; classtype:trojan-activity; sid:2026061602; rev:1;)

# Detect HTTP traffic to tidio.cc C2 payload generation endpoint
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Awesome Motive Supply Chain - HTTP Request to tidio.cc Payload Delivery"; flow:established,to_server; http.host; content:"tidio.cc"; http.uri; content:"/cdn-cgi/l"; reference:url,sansec.io/research/optinmonster-supply-chain-attack; classtype:trojan-activity; sid:2026061603; rev:1;)

# Detect direct connection to known C2 IP
alert ip $HOME_NET any -> 84.201.6.54 any (msg:"MALWARE Awesome Motive Supply Chain - Connection to C2 IP 84.201.6.54"; reference:url,sansec.io/research/optinmonster-supply-chain-attack; classtype:trojan-activity; sid:2026061604; rev:1;)

# Detect XOR key in HTTP payload (credential exfiltration)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Awesome Motive Supply Chain - XOR Key in HTTP Body"; flow:established,to_server; http.request_body; content:"jX9kM2nP4qR6sT8v"; reference:url,sansec.io/research/optinmonster-supply-chain-attack; classtype:trojan-activity; sid:2026061605; rev:1;)
```

Caveat: The XOR key rule (SID 2026061605) may not trigger if the key is only used programmatically within the JavaScript and not transmitted in plaintext in HTTP bodies. The DNS and HTTP host/URI rules are the most reliable network indicators.

---

## Lessons Learned

### 1. CDN-Served Scripts Are a Single Point of Failure

WordPress plugins that load JavaScript from external CDN endpoints create an implicit trust relationship. A compromise of the CDN layer -- even without touching origin servers or plugin code repositories -- can inject malicious payloads into every downstream site. This attack pattern mirrors the [2024 Polyfill.io supply chain attack](https://sansec.io/research/polyfill-supply-chain-attack), also uncovered by Sansec.

**Recommendation:** Implement Subresource Integrity (SRI) hashes for all externally loaded scripts. Plugin vendors should support SRI and pin expected hashes in their plugin code.

### 2. Credential Storage Hygiene on Non-Production Systems

The root cause was a CDN API key stored on a marketing server -- a non-production asset with weaker security posture. The attacker pivoted from this low-value target to the high-value CDN infrastructure.

**Recommendation:** Apply the principle of least privilege to all credential storage. CDN management keys should never reside on internet-facing WordPress installations. Use dedicated secrets management with audit logging.

### 3. Dashboard-Level Visibility Is Insufficient

The backdoor plugin was specifically designed to hide from the WordPress admin dashboard, plugin list, and REST API. Organizations relying solely on dashboard audits would miss this compromise entirely.

**Recommendation:** Implement server-side file integrity monitoring (FIM) on WordPress installations. Direct filesystem and database queries are the only reliable detection methods for this class of attack.

### 4. Short Exposure Windows Still Cause Damage

The OptinMonster/TrustPulse injection lasted only 25 minutes, but the installed backdoor provides persistent access that survives CDN cleanup. Once the backdoor plugin is deployed and admin credentials exfiltrated, the original attack vector is no longer needed.

**Recommendation:** Treat any exposure -- regardless of duration -- as a full compromise requiring complete incident response, including credential rotation and filesystem inspection.

---

## Sources

- [Sansec - OptinMonster Supply Chain Attack Hits 1.2 Million Sites](https://sansec.io/research/optinmonster-supply-chain-attack) -- Primary research and technical analysis
- [Security Affairs - Supply Chain Attack Hits Popular WordPress Plugins Through Awesome Motive CDN](https://securityaffairs.com/193616/malware/supply-chain-attack-hits-popular-wordpress-plugins-through-awesome-motive-cdn.html)
- [The Hacker News - Popular WordPress Plugin Scripts Compromised](https://thehackernews.com/2026/06/popular-wordpress-plugin-scripts.html)
- [BleepingComputer - OptinMonster WordPress Plugin Hacked in CDN Supply-Chain Attack](https://www.bleepingcomputer.com/news/security/optinmonster-wordpress-plugin-hacked-in-cdn-supply-chain-attack/)
- [Patchstack - Supply Chain Attack on OptinMonster, TrustPulse, and PushEngage](https://patchstack.com/articles/supply-chain-attack-on-optinmonster-trustpulse-and-pushengage-tampered-cdn-scripts-auto-creating-rogue-admins/)
- [CyberInsider - Supply Chain Attack Hits OptinMonster Plugin Used in 1.2 Million WordPress Sites](https://cyberinsider.com/supply-chain-attack-hits-optinmonster-plugin-used-in-1-2-million-wordpress-sites/)
- [CVE-2026-10795 - UpdraftPlus Authentication Bypass](https://cvefeed.io/vuln/detail/CVE-2026-10795)
- [FreshySites - UpdraftPlus Vulnerability CVE-2026-10795](https://freshysites.com/security-bulletins/updraftplus-wp-backup-migration-plugin-vulnerability-cve-2026-10795/)
