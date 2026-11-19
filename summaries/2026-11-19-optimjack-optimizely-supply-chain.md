# Technical Analysis Report: OPTIMJACK Supply Chain Attack (2026-11-19)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-19
Version: 1.0

## Executive Summary

On November 16, 2026, a threat actor exploited a vulnerability in Optimizely's Web Experimentation platform signup flow to inject malicious JavaScript into customer projects. The tampered code was served from Optimizely's legitimate CDN (`cdn.optimizely.com`) under a valid certificate, reaching visitors of at least 178 organizations' websites over an approximately 19-hour window (04:21 to 23:11 UTC). Affected sites included CNN, BBC, Zoom, Salesforce, GitLab, IKEA, HSBC, Equifax, Ledger, Peacock, and Air France-KLM.

The payload, tracked as OPTIMJACK, delivered three capabilities: a cryptocurrency wallet address clipper (supporting BTC, ETH, TRON, Solana, TON, LTC, BCH, and DOGE), a payment card skimmer, and an iOS exploit kit router directing Apple device visitors toward the Coruna (iOS 13-17) and DarkSword (iOS 18.x) exploit chains. Approximately $6,600-$7,040 in cryptocurrency receipts was traced to attacker wallets. Optimizely patched the vulnerability and removed all injected code by 23:11 UTC on November 16, posting its incident notice at 01:02 UTC on November 17. Attribution remains unconfirmed.

## Background: Optimizely Web Experimentation

Optimizely Web Experimentation is a widely deployed A/B testing and web optimization platform used by over 110,000 websites. It operates by embedding a JavaScript snippet on customer sites that loads from `cdn.optimizely.com`. The platform includes a "Project JavaScript" field that allows customers to inject custom JavaScript into their projects, which is then served alongside the optimization code through Optimizely's CDN infrastructure. This architecture means that any code placed in the Project JavaScript field is served under Optimizely's domain and TLS certificate, inheriting the trust that sites grant to the vendor's CDN. Report URI researcher Scott Helme identified 1,611 distinct Optimizely snippets across the web during his analysis.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-09-17 | Injector (`webshell[.]lol/get.js`) first observed on Turkish websites via `linkforge[.]cc` |
| 2026-11-09 | iOS exploit router domain `5vobauua3ojpklx[.]icu` registered |
| 2026-11-13 | Kissmetrics and StorifyMe poisoned script responses observed (earlier wave) |
| 2026-11-16, 04:21 | First Optimizely injection detected (BBC snippet), loading `webshell[.]lol` |
| 2026-11-16, 05:23 | Primary payload domain `1688360[.]cc` registered |
| 2026-11-16, 08:10 | First build of `track.js` payload |
| 2026-11-16, 13:03 | First crypto sweep (address swapping active) |
| 2026-11-16, 13:43 | Card skimmer functionality added to payload |
| 2026-11-16, 16:38-19:59 | Second iOS exploit router domain registered |
| 2026-11-16, 17:13-17:57 | Coruna iframe exploit injection for iOS devices begins |
| 2026-11-16, 19:25 | Approximately $7,040 in crypto receipts observed in attacker wallets |
| 2026-11-16, ~20:40 | Mass cleanup of injected code begins |
| 2026-11-16, 23:11 | All tracked Optimizely snippets confirmed clean |
| 2026-11-17, 01:02 | Optimizely publishes incident notice on status.optimizely.com |
| 2026-11-17, 00:37 | `1688360[.]cc` placed on clientHold by registrar |
| 2026-11-17, 03:37 | `webshell[.]lol` suspended by registrar |
| 2026-11-17, 04:11-05:39 | Attacker LTC, TRON, and BTC wallets emptied |

## Root Cause: Optimizely Signup Flow Vulnerability

The attacker exploited a vulnerability in Optimizely's Web Experimentation account signup process. The specific technical details of the flaw have not been publicly disclosed. The attacker leveraged this vulnerability to gain write access to customer Project JavaScript fields, inserting a small JavaScript loader that called out to attacker-controlled infrastructure. Because the Project JavaScript is compiled into the Optimizely CDN snippet, the malicious code was served directly from `cdn.optimizely.com` under Optimizely's valid TLS certificate, inheriting the trust relationship that victim sites had already established with the vendor domain. Optimizely confirmed the entry point and patched the vulnerable signup path.

## Technical Analysis of the Malicious Payload

### 1. Initial Loader Injection (Project JavaScript)

The attacker inserted a compact JavaScript loader into the Project JavaScript field of customer Optimizely projects. Three loader variants were observed:

- **Direct load**: Fetches `1688360[.]cc/track.js` via a dynamically created `<script>` element.
- **Base64-obfuscated**: Uses `atob()` to decode the payload domain, hiding it from literal string searches.
- **Embedded fallback**: Contains a full inline copy of the financial payload (24,392 bytes) that executes via `eval()` if the remote domain is blocked or times out (~2.5 seconds). This variant bypasses domain-based blocking on pages that allow `unsafe-eval` in their CSP.

The loader set global markers `window._k7` and `window.__k7b` to track execution state and prevent re-initialization. The iOS loader variant carried an additional attribute `data-channel-code="02111110"` that linked it to the earlier Kissmetrics/StorifyMe delivery wave.

### 2. Crypto Wallet Address Clipper (track.js)

The primary payload (`track.js`, rebuilt 26 times over the course of the attack day) replaced cryptocurrency wallet addresses on affected pages. Key behaviors:

- Monitors page text, form fields, links, the clipboard (`navigator.clipboard`), and outgoing `fetch`/`XHR` request bodies for cryptocurrency addresses.
- Validates addresses by their chain's checksum before swapping (BTC, ETH/EVM, TRON, Solana, TON, LTC, BCH, DOGE).
- Only replaces addresses appearing near contextual payment terms: "wallet," "deposit," "send," and similar.
- After a swap, exfiltrates non-HttpOnly cookies (up to 8,000 characters) via `document.cookie` and captures a page screenshot using `html2canvas` as a JPEG.
- Uses `navigator.sendBeacon` for data exfiltration to `1688360[.]cc/hit.php`.

### 3. Card Skimmer (Added at 13:43 UTC)

A card skimming module was added to `track.js` in a later build:

- Captures card number, expiry date, and CVV from the site's own form fields using form submit and POST body interception.
- Performs Luhn validation on card numbers before exfiltration.
- Exfiltrates captured data to `1688360[.]cc/card.php`.
- **Limitation**: Cannot read card data entered into cross-origin payment iframes (Stripe Hosted Fields, Adyen, etc.).
- Does not capture cardholder name or billing address.

### 4. iOS Exploit Kit Router (Added at 17:13 UTC)

For visitors on iPhones and iPads, the loader fetches `boot.js` from two `.icu` domains and routes visitors to exploit kits based on iOS version:

- **Coruna** (paths `/A8/`, `/JIUJIU888/`): Targets iOS 13.0 through 17.2.1. Previously documented by Google researchers.
- **DarkSword** (path `/D11/`): Targets iOS 18.4 through 18.7.
- **iOS 26 chain** (path `/C10/`): Fingerprints devices but logs `usable_grade=DEAD weaponized=false`, suggesting collection only.
- Post-exploitation uploads `keychain-2.db`.
- Exploits delivered via hidden iframe with 60-second reload retry loops.
- The kit's own comments mark iOS 18.7.3+ and iOS 26.3+ as patched.
- Coruna telemetry is sent via `POST /api/iptj` to `l7bcsnwc7nzr3uo[.]icu`.

### 5. C2 Infrastructure

| Domain / IP | Role | Registration / Status |
|------------|------|----------------------|
| `1688360[.]cc` | Primary payload host and exfil server | Registered 2026-11-16 05:23 UTC; clientHold 2026-11-17 00:37 |
| `webshell[.]lol` | Injector from earlier wave | Suspended 2026-11-17 03:37 |
| `linkforge[.]cc` | SEO connector for earlier wave | Active |
| `5vobauua3ojpklx[.]icu` | iOS exploit router | Registered 2026-11-09 |
| `eil786npto9u5bq[.]icu` | iOS exploit router | Registered 2026-11-16 |
| `l7bcsnwc7nzr3uo[.]icu` | Coruna telemetry endpoint | Active |
| `je4ft3gn8vxudum[.]icu` | Fallback C2 (boot.js reference) | Active |
| `ioshack[.]icu` | Fallback C2 (boot.js reference) | Active |
| `136.113.106[.]136` | IP for `1688360[.]cc` | Historical |
| `34.96.213[.]201` | GCP-hosted infrastructure | Historical, may be reassigned; retire by 2026-12-19 |
| `34.87.36[.]58` | GCP-hosted infrastructure | Historical, may be reassigned; retire by 2026-12-19 |

### 6. Anti-Forensics and Evasion

- **CDN trust abuse**: Payload served from `cdn.optimizely.com` under a legitimate certificate, bypassing domain-based allowlists and CSP `script-src` entries that trust the vendor.
- **`strict-dynamic` bypass**: Sites using `strict-dynamic` CSP allowed the attack payload to execute because a trusted script (the Optimizely snippet) loaded it.
- **Base64 obfuscation**: `atob()` used to hide the C2 domain from inline text scanning.
- **Inline eval fallback**: Full payload embedded as a fallback with `eval()` to defeat C2 domain blocking.
- **Rapid payload iteration**: 26 builds in a single day, progressively adding functionality and evading hash-based detection.
- **CSP analysis**: Of 159 affected sites analyzed, only 24 fully blocked the payload; 17 limited exfiltration but not address swapping; 50 had permissive policies; 68 had no CSP at all.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `136.113.106[.]136`)

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `1688360[.]cc` | Primary payload/exfil host (track.js, card.php, hit.php) |
| Domain | `webshell[.]lol` | Injector from earlier wave (get.js) |
| Domain | `linkforge[.]cc` | SEO connector for earlier wave |
| Domain | `5vobauua3ojpklx[.]icu` | iOS exploit router (boot.js) |
| Domain | `eil786npto9u5bq[.]icu` | iOS exploit router (boot.js) |
| Domain | `l7bcsnwc7nzr3uo[.]icu` | Coruna telemetry (POST /api/iptj) |
| Domain | `je4ft3gn8vxudum[.]icu` | Fallback C2 |
| Domain | `ioshack[.]icu` | Fallback C2 |
| IP | `136.113.106[.]136` | Resolved from 1688360[.]cc |
| IP | `34.96.213[.]201` | GCP-hosted infrastructure (may be reassigned; retire by 2026-12-19) |
| IP | `34.87.36[.]58` | GCP-hosted infrastructure (may be reassigned; retire by 2026-12-19) |
| URL | `hxxps://1688360[.]cc/track.js` | Malicious payload loader |
| URL | `hxxps://1688360[.]cc/card.php` | Card skimmer exfil endpoint |
| URL | `hxxps://1688360[.]cc/hit.php` | Beacon/data exfil endpoint |
| URL | `hxxps://1688360[.]cc/html2canvas.min.js` | Screenshot capture library |
| URL | `hxxps://webshell[.]lol/get.js` | Injector script |

### File System

| Hash (SHA-256) | Description |
|----------------|-------------|
| `f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40` | track.js — later build |
| `617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3` | track.js — earliest captured build |
| `814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f` | track.js — 17:13 build (with card skimmer) |
| `c2a34c579e4c2e8802752c93b3a9cca0230610f3e4dd6688f4272459c7c7c162` | Decoded inline financial fallback payload |

**Note**: 26 distinct builds of track.js were observed; these hashes cover only specific versions.

### Behavioral

- Global JavaScript variables: `window._k7`, `window.__k7b`
- iOS loader attribute: `data-channel-code="02111110"`
- Dynamic `<script>` injection via `document.createElement('script')` with remote `src`
- `atob()` base64 decoding in Optimizely snippet context
- Clipboard API monitoring (`navigator.clipboard`)
- `navigator.sendBeacon` for data exfiltration
- `html2canvas` JPEG page capture
- `document.cookie` exfiltration (up to 8,000 chars)
- Luhn validation on captured card numbers
- 60-second iframe reload loop (iOS exploit delivery)
- Form submit and XHR/fetch body interception for card data

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into Optimizely's platform, served to visitors via trusted CDN |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Malicious JavaScript payloads (track.js, boot.js) executed in browser context |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication over HTTP/HTTPS to attacker domains |
| T1539 | Steal Web Session Cookie | Cookie theft via document.cookie exfiltration |
| T1056 | Input Capture | Card skimmer intercepting web form submissions and POST bodies |
| T1115 | Clipboard Data | Crypto clipper monitoring and replacing clipboard contents |
| T1113 | Screen Capture | html2canvas JPEG page screenshots |
| T1565.002 | Data Manipulation: Transmitted Data Manipulation | Crypto address replacement in outgoing fetch/XHR requests |
| T1027 | Obfuscated Files or Information | Base64 encoding via atob(), inline eval fallback |
| T1203 | Exploitation for Client Execution | Coruna and DarkSword iOS exploit kit delivery |
| T1041 | Exfiltration Over C2 Channel | Card data and cookies exfiltrated to 1688360[.]cc |

## Impact Assessment

- **Breadth**: At least 178 organizations and their website visitors were exposed over a ~19-hour window. Affected organizations span media (CNN, BBC), technology (Zoom, Salesforce, GitLab, Smartsheet), financial services (HSBC, Equifax, Ledger), retail (IKEA), telecom (TalkTalk, Vodafone AU), and travel (Air France-KLM). Optimizely's own site was also compromised.
- **Financial**: Approximately $6,600-$7,040 in confirmed cryptocurrency theft via wallet address swapping. Card skimming losses are unquantified but payment data was actively exfiltrated.
- **Device compromise**: iOS devices running versions below 18.7.3 or 26.3 were potentially exposed to exploit kit delivery, though no confirmed device compromises were reported. Cynet testing showed conditional delivery rather than confirmed exploitation.
- **Stealth**: The attack was difficult to detect because the payload was served from the vendor's legitimate CDN under a valid certificate. Only 24 of 159 analyzed sites had CSP configurations that blocked the payload.

## Detection & Remediation

### Immediate Detection

**For sites using Optimizely Web Experimentation:**

```bash
# Search for OPTIMJACK indicators in cached/archived Optimizely snippets
grep -rE '1688360|webshell\.lol|atob\(|window\._k7|window\.__k7b|02111110' /path/to/cached/scripts/

# Search proxy/web server logs for C2 domains (adjust paths for your environment)
grep -E '1688360\.cc|webshell\.lol|5vobauua3ojpklx\.icu|eil786npto9u5bq\.icu|l7bcsnwc7nzr3uo\.icu|je4ft3gn8vxudum\.icu|ioshack\.icu|linkforge\.cc' /var/log/proxy/*.log

# Search DNS logs for C2 resolution
grep -E '1688360\.cc|webshell\.lol|5vobauua3ojpklx|eil786npto9u5bq|l7bcsnwc7nzr3uo|je4ft3gn8vxudum|ioshack\.icu' /var/log/dns/*.log

# Check Optimizely Project JavaScript for indicators
# Log into Optimizely > Settings > Project JavaScript for each project
# Search for: 1688360, atob(, eval(, unfamiliar script URLs
```

**Splunk query for proxy logs (from Sigma conversion):**

```spl
"cs-host" IN ("*1688360.cc", "*webshell.lol", "*5vobauua3ojpklx.icu", "*eil786npto9u5bq.icu", "*l7bcsnwc7nzr3uo.icu", "*je4ft3gn8vxudum.icu", "*ioshack.icu", "*linkforge.cc")
```

### Remediation

1. **Inspect Optimizely Projects**: Review Project JavaScript and experiment custom code in every project for `1688360`, `atob(`, `eval(`, or unfamiliar scripts. Remove any unauthorized code.
2. **Credential rotation**: Rotate all Optimizely API tokens, user passwords, and integration credentials with write access.
3. **Card data exposure**: Treat card data entered on affected sites between 04:21 and 23:11 UTC on November 16 as potentially compromised. Notify payment processors and consider customer notification.
4. **Cookie/session rotation**: Rotate session tokens and secrets stored in non-HttpOnly cookies.
5. **iOS device assessment**: Advise users to update to iOS 18.7.3+ or iOS 26.3+. Devices on iOS 18.6 or earlier that visited affected sites should be assessed for compromise.
6. **Log preservation**: Preserve all proxy logs, DNS logs, CSP reports, web server access logs, and cached script responses from November 16 for forensic analysis.
7. **Block IOCs**: Add the domains and IPs listed above to network blocklists. Note: do NOT block `cdn.optimizely.com` itself as it is a legitimate vendor CDN.
8. **Request vendor telemetry**: Ask Optimizely for details on which project IDs were modified, when, and from which source.

### Long-Term Hardening

1. **Content Security Policy**: Deploy strict `script-src` and `connect-src` CSP directives. Note that simply allowlisting `cdn.optimizely.com` does not help; consider hash-based or nonce-based policies. Avoid `strict-dynamic` and `unsafe-eval` as both allow the attack payload to execute.
2. **Third-party script isolation**: Remove third-party tags from authentication and checkout pages. Isolate payment collection in hardened, cross-origin iframes (Stripe Hosted Fields, Adyen, etc.).
3. **Subresource Integrity (SRI)**: Where possible, pin third-party script hashes. Note that dynamic scripts like Optimizely snippets change frequently, limiting SRI applicability.
4. **Script monitoring**: Implement continuous monitoring of third-party scripts for unexpected changes using tools like Report URI, PerimeterX, or similar.
5. **Vendor risk assessment**: Evaluate signup and API access flows of third-party JavaScript vendors for abuse potential.

## Detection Rules

The following detection rules cover OPTIMJACK's known network IOCs (C2 domains, payload URLs, infrastructure IPs) and malicious JavaScript patterns. All IOC-based rules are high confidence due to the specificity of the domains and paths. The main limitation is that these rules detect only the known infrastructure; a future campaign with new domains would evade them.

### Sigma Rules

#### OPTIMJACK DNS Query to Known C2 or Payload Domains

Detects DNS queries to domains used by OPTIMJACK for payload delivery, exfiltration, and iOS exploit routing.

<!-- audit: IOC-based rule matching 8 specific attacker-controlled domains. All domains are unique to OPTIMJACK infrastructure; no legitimate use known. sigma convert to splunk exit 0, to log_scale exit 0. sigma check failed due to environment issue (MITRE ATT&CK data fetch 403), not rule syntax. YAML parse valid. -->

```yaml
title: OPTIMJACK DNS Query to Known C2 or Payload Domains
id: 7a1c3e9b-4f2d-48a6-b5c7-1d8e0f3a2b9c
status: experimental
description: >
    Detects DNS queries to domains used by the OPTIMJACK supply chain attack
    for payload delivery, data exfiltration, and iOS exploit kit routing.
references:
    - https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
    - https://thehackernews.com/2026/11/hijacked-optimizely-scripts-served-card.html
author: Actioner
date: 2026-11-19
tags:
    - attack.t1071.001
    - attack.t1195.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '1688360.cc'
            - 'webshell.lol'
            - '5vobauua3ojpklx.icu'
            - 'eil786npto9u5bq.icu'
            - 'l7bcsnwc7nzr3uo.icu'
            - 'je4ft3gn8vxudum.icu'
            - 'ioshack.icu'
            - 'linkforge.cc'
    condition: selection
falsepositives:
    - Unlikely given the specificity of these domains
level: high
```

compile: sigma convert splunk/log_scale exit 0 | confidence: **high** (IOC-specific)

#### OPTIMJACK Proxy Access to Malicious Payload URLs

Detects HTTP/HTTPS requests to known OPTIMJACK payload URLs and C2 domains in proxy logs.

<!-- revision: removed selection_uri OR leg — /track.js, /boot.js, /get.js, /html2canvas.min.js are common filenames that caused FPs on any domain. Now domain-only. sigma convert splunk exit 0, log_scale exit 0. -->

```yaml
title: OPTIMJACK Proxy Access to Malicious Payload URLs
id: 2b4d6f8a-1c3e-5a7b-9d0f-4e2c8a6b1d3e
status: experimental
description: >
    Detects HTTP/HTTPS proxy requests to known OPTIMJACK C2 and payload
    domains used for payload delivery, card skimmer exfiltration, and
    iOS exploit kit routing.
references:
    - https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
    - https://thehackernews.com/2026/11/hijacked-optimizely-scripts-served-card.html
author: Actioner
date: 2026-11-19
tags:
    - attack.t1071.001
    - attack.t1195.002
logsource:
    category: proxy
detection:
    selection_domain:
        cs-host|endswith:
            - '1688360.cc'
            - 'webshell.lol'
            - '5vobauua3ojpklx.icu'
            - 'eil786npto9u5bq.icu'
            - 'l7bcsnwc7nzr3uo.icu'
            - 'je4ft3gn8vxudum.icu'
            - 'ioshack.icu'
            - 'linkforge.cc'
    condition: selection_domain
falsepositives:
    - Unlikely given the specificity of these domains
level: high
```

compile: sigma convert splunk/log_scale exit 0 | confidence: **high** (IOC-specific)

#### OPTIMJACK Network Connection to Known C2 IP Addresses

Detects outbound connections to IP addresses associated with OPTIMJACK infrastructure.

<!-- revision: added GCP IP expiry (review-by 2026-12-19) to description and false-positive note. sigma convert splunk exit 0, log_scale exit 0. -->

```yaml
title: OPTIMJACK Network Connection to Known C2 IP Addresses
id: 9c5e7a1b-3d2f-4b6a-8e0c-2f4d6a8b1c3e
status: experimental
description: >
    Detects outbound network connections to IP addresses associated with
    the OPTIMJACK supply chain attack infrastructure. GCP IPs (34.96.213.201,
    34.87.36.58) may be reassigned; review and retire by 2026-12-19.
references:
    - https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
    - https://phoenix.security/optimjack-optimizely-supply-chain-attack-card-skimmer-ios/
author: Actioner
date: 2026-11-19
tags:
    - attack.t1071.001
    - attack.t1195.002
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
            - '136.113.106.136'
            - '34.96.213.201'
            - '34.87.36.58'
    condition: selection
falsepositives:
    - The GCP IP addresses 34.96.213.201 and 34.87.36.58 may be reassigned to legitimate services over time
level: high
```

compile: sigma convert splunk/log_scale exit 0 | confidence: **high** (IOC-specific; GCP IPs time-limited)

### Suricata Rules

Ten Suricata rules covering DNS queries to all eight C2/payload/exploit domains and HTTP requests to the track.js and card.php endpoints.

> **SID range note:** SIDs 2100101-2100110 fall within the Emerging Threats reserved range. Remap to your local SID allocation (e.g., 1000001+) before production deployment.

<!-- revision: added SID-range conflict note. suricata -T exit 0. -->

```
# NOTE: SIDs 2100101-2100110 are in the ET reserved range. Remap before production use.

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to Payload Domain 1688360.cc"; flow:to_server; dns.query; content:"1688360.cc"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-19; sid:2100101; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to Injector Domain webshell.lol"; flow:to_server; dns.query; content:"webshell.lol"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-19; sid:2100102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to iOS Exploit Router 5vobauua3ojpklx.icu"; flow:to_server; dns.query; content:"5vobauua3ojpklx.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-19; sid:2100103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to iOS Exploit Router eil786npto9u5bq.icu"; flow:to_server; dns.query; content:"eil786npto9u5bq.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-19; sid:2100104; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to Coruna Telemetry l7bcsnwc7nzr3uo.icu"; flow:to_server; dns.query; content:"l7bcsnwc7nzr3uo.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-19; sid:2100105; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to Fallback C2 je4ft3gn8vxudum.icu"; flow:to_server; dns.query; content:"je4ft3gn8vxudum.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-19; sid:2100106; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to Fallback C2 ioshack.icu"; flow:to_server; dns.query; content:"ioshack.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-19; sid:2100107; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to Linkforge SEO Connector linkforge.cc"; flow:to_server; dns.query; content:"linkforge.cc"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-19; sid:2100108; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK HTTP Request to track.js Payload Loader"; flow:established,to_server; http.host; content:"1688360.cc"; http.uri; content:"/track.js"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-19; sid:2100109; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK HTTP POST to Card Skimmer Exfil Endpoint"; flow:established,to_server; http.method; content:"POST"; http.host; content:"1688360.cc"; http.uri; content:"/card.php"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-19; sid:2100110; rev:1;)
```

compile: suricata -T exit 0 | confidence: **high** (IOC-specific)

### YARA Rules

Four YARA rules detecting OPTIMJACK JavaScript payload patterns and known hashes.

<!-- revision: Rule 4 (TrackJS_Hash) rewritten — was bare string "1688360" matching any file; now uses import "hash" with hash.sha256(0, filesize) against the 4 known SHA-256 hashes. yarac exit 0 on all 4 rules. -->

```yara
import "hash"

rule Supply_Chain_OPTIMJACK_TrackJS_Loader
{
    meta:
        description = "Detects OPTIMJACK malicious track.js payload loader and card skimmer JavaScript served through compromised Optimizely snippets"
        author = "Actioner"
        date = "2026-11-19"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        hash = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"
        severity = "high"
        tlp = "WHITE"

    strings:
        $domain1 = "1688360.cc" ascii wide
        $domain2 = "webshell.lol" ascii wide
        $path1 = "/track.js" ascii wide
        $path2 = "/card.php" ascii wide
        $path3 = "/hit.php" ascii wide
        $global1 = "window._k7" ascii
        $global2 = "window.__k7b" ascii
        $channel = "02111110" ascii

    condition:
        filesize < 500KB and
        (
            (1 of ($domain*) and 1 of ($path*)) or
            (2 of ($global*, $channel) and 1 of ($domain*))
        )
}

rule Supply_Chain_OPTIMJACK_iOS_Exploit_Router
{
    meta:
        description = "Detects OPTIMJACK iOS exploit routing JavaScript that directs visitors to Coruna and DarkSword exploit kits"
        author = "Actioner"
        date = "2026-11-19"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        severity = "high"
        tlp = "WHITE"

    strings:
        $icu1 = "5vobauua3ojpklx.icu" ascii wide
        $icu2 = "eil786npto9u5bq.icu" ascii wide
        $icu3 = "l7bcsnwc7nzr3uo.icu" ascii wide
        $icu4 = "je4ft3gn8vxudum.icu" ascii wide
        $icu5 = "ioshack.icu" ascii wide
        $exploit_path1 = "/A8/" ascii
        $exploit_path2 = "/JIUJIU888/" ascii
        $exploit_path3 = "/D11/" ascii
        $exploit_path4 = "/C10/" ascii
        $boot = "boot.js" ascii
        $channel = "data-channel-code" ascii

    condition:
        filesize < 500KB and
        (
            2 of ($icu*) or
            (1 of ($icu*) and 1 of ($exploit_path*)) or
            (1 of ($icu*) and ($boot or $channel))
        )
}

rule Supply_Chain_OPTIMJACK_Crypto_Clipper
{
    meta:
        description = "Detects OPTIMJACK crypto wallet address clipper JavaScript that replaces cryptocurrency addresses on web pages"
        author = "Actioner"
        date = "2026-11-19"
        reference = "https://thehackernews.com/2026/11/hijacked-optimizely-scripts-served-card.html"
        severity = "high"
        tlp = "WHITE"

    strings:
        $clipboard = "navigator.clipboard" ascii
        $beacon = "navigator.sendBeacon" ascii
        $html2canvas = "html2canvas" ascii
        $cookie_exfil = "document.cookie" ascii
        $wallet_term1 = "wallet" ascii nocase
        $wallet_term2 = "deposit" ascii nocase
        $domain = "1688360.cc" ascii wide
        $global1 = "window._k7" ascii
        $global2 = "window.__k7b" ascii

    condition:
        filesize < 500KB and
        $domain and
        (
            ($clipboard and 1 of ($wallet_term*)) or
            ($beacon and $html2canvas) or
            (1 of ($global*) and $cookie_exfil)
        )
}

rule Supply_Chain_OPTIMJACK_TrackJS_Hash
{
    meta:
        description = "Detects known OPTIMJACK track.js samples by SHA-256 file hash"
        author = "Actioner"
        date = "2026-11-19"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        hash1 = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"
        hash2 = "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3"
        hash3 = "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f"
        hash4 = "c2a34c579e4c2e8802752c93b3a9cca0230610f3e4dd6688f4272459c7c7c162"
        severity = "critical"
        tlp = "WHITE"

    condition:
        filesize < 500KB and
        (
            hash.sha256(0, filesize) == "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40" or
            hash.sha256(0, filesize) == "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3" or
            hash.sha256(0, filesize) == "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f" or
            hash.sha256(0, filesize) == "c2a34c579e4c2e8802752c93b3a9cca0230610f3e4dd6688f4272459c7c7c162"
        )
}
```

compile: yarac exit 0 | confidence: **high** (Rules 1-3: pattern-based with IOC anchors), **high** (Rule 4: exact SHA-256 hash matching via `import "hash"`)

<!-- revision: removed hollow Snort section — no actual Snort rules were provided or validated. -->

## Lessons Learned

1. **Third-party CDN trust is fragile**: The OPTIMJACK attack demonstrates that allowlisting a vendor's CDN domain in Content Security Policy is insufficient when the vendor's platform itself is compromised. The malicious code was served from `cdn.optimizely.com` under a valid certificate, inheriting the trust that sites had already granted.

2. **`strict-dynamic` and `unsafe-eval` are attack enablers**: Sites using `strict-dynamic` CSP allowed the payload because a trusted script loaded it. The embedded `eval()` fallback defeated domain-based blocking. Only nonce-based or hash-based CSP configurations with no eval offered protection.

3. **Third-party scripts on payment pages are a critical risk**: Sites that collected card data through their own forms (rather than cross-origin payment iframes) exposed cardholder data. Payment collection should always be isolated in the payment provider's hosted fields.

4. **Supply chain attacks benefit from rapid iteration**: The attacker rebuilt the payload 26 times in a single day, progressively adding capabilities (crypto clipper, card skimmer, iOS exploits). Hash-based detection alone is insufficient; behavioral and domain-based rules provide broader coverage.

5. **Multi-vendor supply chains amplify blast radius**: The same actor also poisoned Kissmetrics, StorifyMe, and Minute Media scripts, suggesting a systematic campaign against web optimization platforms rather than a targeted attack on Optimizely alone.

## Sources

- [Unit 42 - Borrowed Code, Real Consequences: What OPTIMJACK Teaches Us](https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/) — Primary technical analysis by Palo Alto Networks
- [The Hacker News - Hijacked Optimizely Scripts Served Card Skimmer and iOS Exploit Kits](https://thehackernews.com/2026/11/hijacked-optimizely-scripts-served-card.html) — Detailed IOCs, timeline, and payload analysis
- [Phoenix Security - Optimizely Supply Chain Attack: OPTIMJACK Skimmer IOCs](https://phoenix.security/optimjack-optimizely-supply-chain-attack-card-skimmer-ios/) — Comprehensive IOC listing, obfuscation techniques, and exploit kit details
- [ReversingLabs - OPTIMJACK: When Trusted JavaScript Becomes a Supply Chain Attack](https://www.reversinglabs.com/blog/optimjack-when-trusted-javascript-becomes-a-supply-chain-attack) — CSP analysis, hunting guidance, and detection recommendations
- [The Register - Optimizely hack turns world's biggest websites into malware dispensers](https://www.theregister.com/cyber-crime/2026/11/17/optimizely-hack-turns-worlds-biggest-websites-into-malware-dispensers/5310448) — Media coverage and vendor response
- [Security Affairs - OPTIMJACK: BBC, CNN and Zoom Among Targets](https://securityaffairs.com/203289/malware/optimjack-bbc-cnn-and-zoom-among-targets-of-optimizely-script-hijacking.html) — Incident summary
- [Cloud Security Alliance - OPTIMJACK Research Note](https://labs.cloudsecurityalliance.org/research/csa-research-note-optimjack-optimizely-script-supply-chain-2/) — CSP and supply chain risk analysis
- [Decryption Digest - Optimizely Supply Chain Attack: OPTIMJACK Hits 178](https://www.decryptiondigest.com/blog/optimjack-optimizely-supply-chain-attack-2026) — Attribution analysis and incident summary
- [SecurityWeek - Ad Tech Company Optimizely Confirms Cyberattack](https://www.securityweek.com/ad-tech-company-optimizely-confirms-cyberattack/amp/) — Vendor confirmation of the compromise

---
*Report generated by Actioner*
