# Technical Analysis Report: OPTIMJACK Optimizely Web Supply Chain Attack (2026-11-21)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-21
Version: 1.0 DRAFT

## Executive Summary

On November 16, 2026, an attacker exploited a vulnerability in the Optimizely Web Experimentation platform to inject malicious JavaScript into the Project JavaScript field of customer accounts. The tampered code was served from Optimizely's legitimate CDN (`cdn.optimizely.com`) under its own valid TLS certificate, bypassing most Content Security Policy configurations. At least 188 snippets belonging to 178 organizations were infected, including BBC, CNN, Zoom, Salesforce, GitLab, IKEA, HSBC, Equifax, Air France-KLM, Ledger, and Peacock. The multi-stage payload performed cryptocurrency address swapping across eight blockchain networks, payment card skimming via form interception, cookie and screenshot theft, and delivered the Coruna and DarkSword iOS exploit kits targeting devices running iOS 13 through 18.6. Approximately $7,150 in cryptocurrency was confirmed stolen; the number of compromised payment card records remains unknown. Optimizely remediated the vulnerability and cleaned all infected snippets by 23:11 UTC on November 16.

## Background: Optimizely Web Experimentation

Optimizely Web Experimentation is a widely deployed A/B testing and personalization platform used by enterprise websites. Sites embed an Optimizely JavaScript snippet (typically loaded from `cdn.optimizely.com/js/<project_id>.js`) that fires on every page load, prior to any user consent gating. The snippet includes a Project JavaScript field that runs arbitrary customer-provided code on every visitor's browser. This field, combined with the fact that the snippet executes on page load from a trusted CDN origin, made it a high-value target for supply chain injection. Optimizely's own documentation recommends including `'unsafe-eval'` in CSP configurations, which further weakened defenses for many affected sites.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-09-17 | `webshell[.]lol` injector first appears on Turkish sites via SEO panel script |
| 2026-11-09 17:52 | `5vobauua3ojpklx[.]icu` iOS exploit router domain registered |
| 2026-11-13 to 2026-11-16 | Earlier wave injects `webshell[.]lol/get.js` through Kissmetrics, StorifyMe, and Minute Media scripts |
| 2026-11-16 02:21 | Last clean capture of the BBC Optimizely snippet |
| 2026-11-16 04:21 | First Optimizely injection observed (BBC snippet) |
| 2026-11-16 04:28-05:23 | TLS certificates issued for `1688360[.]cc`; domain registered at 05:23 |
| 2026-11-16 08:10 | First build of `track.js` payload (crypto clipper functionality) |
| 2026-11-16 08:28 | `track.js` first observed on bbc.com |
| 2026-11-16 11:20 | Zoom Optimizely snippet modified |
| 2026-11-16 13:03-13:05 | Attacker sweeps stolen cryptocurrency to exchange addresses |
| 2026-11-16 13:43 | Card skimmer module added to payload |
| 2026-11-16 16:38 | `eil786npto9u5bq[.]icu` iOS exploit domain registered |
| 2026-11-16 17:13-17:57 | iOS exploit infrastructure activated; Coruna iframe injected for iOS 18.6 and earlier |
| 2026-11-16 19:24-19:59 | Report URI sweep finds 186 of 1,611 snippets infected |
| 2026-11-16 ~20:40-21:10 | Mass cleanup begins (Ledger, Smartsheet, BBC) |
| 2026-11-16 21:52 | Only TalkTalk snippet still infected |
| 2026-11-16 23:11 | All infected snippets confirmed clean |
| 2026-11-17 00:37 | `1688360[.]cc` placed on clientHold (domain suspended) |
| 2026-11-17 01:02 | Optimizely publishes incident notice |
| 2026-11-17 03:37 | `webshell[.]lol` placed on clientHold |

## Root Cause: Optimizely Platform Vulnerability Exploitation

The attacker exploited a vulnerability in Optimizely's Web Experimentation platform that allowed unauthorized modification of the Project JavaScript field in customer accounts. The injected code was then served directly from `cdn.optimizely.com` under Optimizely's own TLS certificate, making it indistinguishable from legitimate Optimizely functionality. The exact vulnerability has not been publicly disclosed, but Optimizely confirmed "an unauthorized party exploited a vulnerability" and subsequently blocked access to the vulnerable path, deployed a fix, ended active sessions, revoked tokens, and reset access for affected accounts. Smartsheet was re-infected after an initial cleanup, indicating the attacker retained access until full remediation.

## Technical Analysis of the Malicious Payload

### 1. Injection via Optimizely Project JavaScript

The attacker wrote a loader into each project's Project JavaScript field while leaving the rest of the Optimizely snippet untouched. Three loader variants were observed:

- **Version 1 (plain loader):** Dynamically creates a `<script>` element with `src` set to `hxxps://1688360[.]cc/track.js`, appended to `document.head` or `documentElement` with `async` set.
- **Version 2 (obfuscated loader):** The C2 URL is base64-encoded and decoded at runtime with `atob()`. Plain-text search for the domain name does not detect this variant.
- **Version 3 (inline fallback):** Contains a full copy of the payload that runs through `eval()` if the external domain is blocked, defeating CSP `connect-src` restrictions.

The payload was rebuilt 26 times during the single-day campaign, with global JavaScript markers `window._k7` and `window.__k7b` used for execution control.

### 2. Crypto Address Clipper (track.js)

The primary payload (`track.js`) replaces valid cryptocurrency wallet addresses across eight blockchain networks (BTC, ETH/EVM, TRON, Solana, TON, LTC, BCH, DOGE). The clipper validates addresses using each chain's checksum algorithm and only triggers replacement when the address appears near payment-related keywords ("wallet," "deposit," "send"). Replacement targets include:

- Page text content and form fields
- Hyperlinks and image alt text
- The browser clipboard (`navigator.clipboard`)
- Outgoing `fetch`/`XMLHttpRequest` requests
- `window.open` navigations
- The iOS share sheet
- DOM changes (via MutationObserver, rescanning on change)

### 3. Card Skimmer (added 13:43 UTC)

Added approximately nine hours after the initial injection, the card skimmer monitors form submissions and `fetch`/`XMLHttpRequest` POST requests for Luhn-valid card numbers, expiry dates, and CVV codes. Captured card data is exfiltrated to `hxxps://1688360[.]cc/card.php` via `navigator.sendBeacon`. The skimmer cannot read card data inside cross-origin hosted payment iframes (e.g., Stripe Hosted Fields, Adyen), limiting its effectiveness on sites that use third-party payment processing.

### 4. Cookie and Screenshot Theft

When a wallet address swap occurs near wallet- or payment-related wording, the payload sends the current page URL, all non-HttpOnly cookies, the original and swapped addresses, and an html2canvas screenshot to `hxxps://1688360[.]cc/hit.php`. The screenshot library (`html2canvas.min.js`) is loaded from the same C2 domain.

### 5. iOS Exploit Kit Delivery (17:13-17:57 UTC)

Starting at 17:13 UTC, the payload began loading `boot.js` from two `.icu` domains, which reads the iOS version and opens a matching exploit chain in a hidden iframe:

- **Coruna** (iOS 13.0 to 17.2.1): Loaded from paths `/A8/` and `/JIUJIU888/index.js`, with telemetry sent to `l7bcsnwc7nzr3uo[.]icu` via `POST /api/iptj` using channel code `BIGNIAO`.
- **DarkSword** (iOS 18.4 to 18.7): Loaded from paths `/B9/`, `/D11/`, `/D12/`.
- **iOS 26 fingerprinting** (iOS 26.x): Loaded from path `/C10/`, currently only collecting device details.

A Coruna iframe was added to every visit from iOS 18.6 or earlier, with the page reloading every 60 seconds to retry the exploit. Kit comments indicate iOS 18.7.3+ and iOS 26.3+ are patched.

### 6. C2 Infrastructure

| Component | Domain/IP | Purpose |
|-----------|-----------|---------|
| Primary C2 | `1688360[.]cc` (136.113.106[.]136) | Payload hosting, card/cookie exfiltration |
| iOS Router 1 | `5vobauua3ojpklx[.]icu` (34.96.213[.]201) | `boot.js` exploit loader |
| iOS Router 2 | `eil786npto9u5bq[.]icu` (34.87.36[.]58) | Coruna and iOS 26 exploit pages |
| Coruna Telemetry | `l7bcsnwc7nzr3uo[.]icu` | Exploit kit callback |
| Injector | `webshell[.]lol` | Earlier wave `get.js` injector |
| SEO Panel | `linkforge[.]cc` | SEO backlink script carrying the injector |
| Fallback C2 | `je4ft3gn8vxudum[.]icu` | Hardcoded in `boot.js` |
| Fallback C2 | `q1ls1ho9x7wsxlu[.]icu` | Hardcoded in `boot.js` |
| Fallback C2 | `ios-hack[.]icu` | Hardcoded in `boot.js` |
| Related | `p55abnw2pnsz0bo[.]icu` | Shared certificates/IPs with kit |
| Related | `1y69gy2mdzaltz1[.]icu` | Shared certificates/IPs with kit |
| Related | `gm38duxoihbmy5o[.]icu` | Shared certificates/IPs with kit |

Exfiltration paths on `1688360[.]cc`:
- `/track.js` -- main payload delivery
- `/card.php` -- card data exfiltration via `navigator.sendBeacon`
- `/hit.php` -- cookie, URL, and screenshot exfiltration
- `/html2canvas.min.js` -- screenshot library

### 7. Anti-Forensics / Evasion Techniques

- **Trusted CDN delivery:** Payload served from `cdn.optimizely.com` under a valid Optimizely TLS certificate, blending with legitimate traffic.
- **Base64 obfuscation (Version 2):** C2 domain encoded with `atob()` to evade string-based detection.
- **Inline eval fallback (Version 3):** Full payload copy that executes via `eval()` if external C2 is blocked.
- **Rapid rebuilds:** Payload rebuilt 26 times in one day, generating different hashes for each version.
- **Checksum-aware targeting:** Crypto address replacement only triggers for valid addresses near payment keywords, reducing noise and detection.
- **Conditional iOS exploit delivery:** Exploit kit iframes only injected for specific iOS version ranges.
- **`strict-dynamic` bypass:** Sites using `'strict-dynamic'` CSP trusted scripts inserted by the Optimizely snippet, letting the payload through.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### File System

| File | Hash (SHA-256) | Description |
|------|---------------|-------------|
| track.js (17:57 build) | `f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40` | Final payload build |
| track.js (earliest) | `617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3` | Earliest known payload |
| track.js (17:13 build) | `814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f` | Build with iOS exploit stage |

**Note:** The payload was rebuilt 26 times during the campaign day. These hashes cover only three known versions.

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `1688360[.]cc` | Primary C2: payload hosting and exfiltration |
| Domain | `webshell[.]lol` | Injector (earlier wave) |
| Domain | `5vobauua3ojpklx[.]icu` | iOS exploit router |
| Domain | `eil786npto9u5bq[.]icu` | iOS exploit router (Coruna, iOS 26) |
| Domain | `l7bcsnwc7nzr3uo[.]icu` | Coruna telemetry |
| Domain | `je4ft3gn8vxudum[.]icu` | Fallback C2 (hardcoded in boot.js) |
| Domain | `q1ls1ho9x7wsxlu[.]icu` | Fallback C2 (hardcoded in boot.js) |
| Domain | `ios-hack[.]icu` | Fallback C2 (hardcoded in boot.js) |
| Domain | `p55abnw2pnsz0bo[.]icu` | Related infrastructure |
| Domain | `1y69gy2mdzaltz1[.]icu` | Related infrastructure |
| Domain | `gm38duxoihbmy5o[.]icu` | Related infrastructure |
| Domain | `linkforge[.]cc` | SEO panel script carrying injector |
| IP | `136.113.106[.]136` | Resolved IP for `1688360[.]cc` |
| IP | `34.96.213[.]201` | Resolved IP for `5vobauua3ojpklx[.]icu` |
| IP | `34.87.36[.]58` | Resolved IP for `eil786npto9u5bq[.]icu` |
| URL Pattern | `hxxps://1688360[.]cc/track.js` | Main payload delivery |
| URL Pattern | `hxxps://1688360[.]cc/card.php` | Card data exfiltration |
| URL Pattern | `hxxps://1688360[.]cc/hit.php` | Cookie/screenshot exfiltration |
| URL Pattern | `hxxps://1688360[.]cc/html2canvas.min.js` | Screenshot library |

### Cryptocurrency Wallets (Attacker)

| Asset | Address |
|-------|---------|
| BTC | `19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW` |
| ETH/EVM (also BSC) | `0xC4026b06D82b0F0B363eda0642D61CfbDc17884e` |
| TRON | `THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa` |
| SOL | `FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n` |
| TON | `UQAgM1VqSZQiJLSG5w-ovurq5CZdxLEK3_7CMmwALTA5e09p` |
| LTC | `ltc1q3wp7g6ds0ggg6fl6kncpa4sepn0q3qfacgred5` |
| BCH | `qzkaaf8n6grmpr0d9lx8xutn3r9lk722f566hhpe58` |
| DOGE | `DBEGrxRF7KMSuhTS4c1MFviStU6efdMnu5` |

**Cash-out/sweep addresses:**

| Asset | Address |
|-------|---------|
| LTC | `ltc1qpxvjs8u8awg8pvpwmssqlj3gzugd9vtwjtc5fc` |
| USDT (TRON) | `TMLQvDvpgSyx94maptc3TxvmCVtT5qHVup` (active since March 2026) |
| BTC | `bc1q5fljq9c4g7gsjgg4etpn6k3lyusahcvjfv0u99` |

### Behavioral

- JavaScript global markers `window._k7` and `window.__k7b` set by the payload
- `data-channel-code="02111110"` attribute on injected script tags
- Coruna telemetry channel code string `BIGNIAO`
- Dynamic `<script>` element creation pointing to `1688360[.]cc`
- Base64-encoded C2 URLs decoded via `atob()`
- `eval()` execution of inline payload fallback
- `navigator.sendBeacon` used for card data exfiltration
- Hidden iframes for iOS exploit delivery with 60-second page reload
- MutationObserver monitoring DOM changes for crypto address replacement

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Compromise Software Supply Chain | Injected malicious JS into Optimizely platform, served from legitimate CDN to 178 organizations |
| T1059.007 | JavaScript | Payload executed as JavaScript in victim browsers via trusted Optimizely snippet |
| T1185 | Browser Session Hijacking | Stole non-HttpOnly cookies and browser session data via injected JavaScript |
| T1539 | Steal Web Session Cookie | Exfiltrated non-HttpOnly cookies to `1688360[.]cc/hit.php` |
| T1056.003 | Web Portal Capture | Card skimmer captured payment card numbers, expiry dates, and CVVs from form fields |
| T1565.002 | Transmitted Data Manipulation | Crypto address clipper replaced valid wallet addresses with attacker-controlled addresses in page content, clipboard, and outgoing requests |
| T1041 | Exfiltration Over C2 Channel | Stolen card data, cookies, and screenshots exfiltrated to `1688360[.]cc` endpoints |
| T1189 | Drive-by Compromise | Coruna and DarkSword iOS exploit kits delivered via hidden iframes to vulnerable iOS devices |
| T1203 | Exploitation for Client Execution | iOS exploit chains targeting CVEs in iOS 13-18.6 for code execution |
| T1027 | Obfuscated Files or Information | Base64-encoded C2 URLs (`atob()`), eval fallback, 26 payload rebuilds in one day |
| T1071.001 | Web Protocols | All C2 communication over HTTPS |

## Impact Assessment

- **Breadth:** 188 Optimizely snippets across 178 organizations infected, spanning banking (32), technology (23), retail (20), streaming (12), media (10), airlines (9), healthcare (8), and multiple other sectors. The actual number is likely higher as only 1,611 snippets were checked.
- **Depth:** Multi-purpose payload combining financial theft (card skimming + crypto clipping), session hijacking, and zero-click iOS exploitation. Sites with forms processing direct card input (not iframe-hosted payment fields) were most severely impacted.
- **Financial impact:** Approximately $7,150 in confirmed cryptocurrency theft. Payment card exposure remains unquantified.
- **Stealth:** Payload served from the trusted `cdn.optimizely.com` origin with a valid certificate, bypassing most CSP configurations. Only 24 of 159 evaluated sites (15%) had CSPs restrictive enough to fully block the payload.
- **Exposure window:** Approximately 16 hours (04:21 to ~20:40 UTC on November 16). Card skimming active for approximately 7 hours (13:43 to ~20:40 UTC).

## Detection & Remediation

### Immediate Detection

**Search Optimizely Project JavaScript and custom experiment code for:**
```
1688360
atob(
.icu
track.js
webshell.lol
window._k7
window.__k7b
```

**Review proxy/web logs from 08:00 UTC November 16 onward for connections to:**
```
1688360.cc
webshell.lol
5vobauua3ojpklx.icu
eil786npto9u5bq.icu
l7bcsnwc7nzr3uo.icu
```

**Fetch every Optimizely snippet your site serves and record its Last-Modified header.** Compare against known-clean versions.

### Remediation

1. **Immediate:** Contact Optimizely to confirm which project IDs were affected, when changes occurred, and the method of access.
2. **Credential rotation:** Rotate all Optimizely user passwords, API tokens, and integration credentials with write access.
3. **Card exposure:** Treat any payment card data entered on affected sites between 13:43 and ~21:00 UTC November 16 as potentially compromised. Notify payment processors and consider PCI breach notification obligations.
4. **Cookie rotation:** Rotate any secrets stored in non-HttpOnly cookies that were active during the exposure window.
5. **iOS advisory:** Advise visitors to update iOS to 18.7.3+ or 26.3+.
6. **Cryptocurrency verification:** Warn users who performed cryptocurrency transactions during the exposure window to verify destination addresses.

### Long-Term Hardening

1. **Content Security Policy:** Deploy restrictive CSPs with explicit `script-src` allowlists (not `'strict-dynamic'` or `'unsafe-eval'`), tight `connect-src` restrictions to block exfiltration, and CSP reporting enabled.
2. **Subresource Integrity (SRI):** Where possible, pin Optimizely snippet hashes with SRI attributes to detect tampering.
3. **Third-party script monitoring:** Implement continuous monitoring of third-party JavaScript (Report URI, PerimeterX, or similar) to detect unauthorized changes.
4. **Payment isolation:** Use cross-origin iframes for payment processing (Stripe Elements, Adyen, etc.) to prevent JavaScript-based card skimming from the parent page.
5. **Vendor security assessment:** Review third-party vendors with JavaScript execution privileges for security posture, breach notification SLAs, and access controls.

## Detection Rules

Three Sigma rules, two YARA rules, eight Suricata rules, and three Snort rules detect OPTIMJACK infrastructure access, payload content, and exfiltration activity. All rules target specific, confirmed IOCs from the November 16 campaign; note that the C2 domain `1688360[.]cc` was placed on clientHold November 17 and may not resolve in future campaigns by the same actor, so the behavioral YARA patterns provide longer-term detection value.

### Sigma: OPTIMJACK C2 Domain Access via Proxy

Detects web proxy requests to any of the twelve known OPTIMJACK C2 and infrastructure domains.

compile: splunk pass, log_scale pass | confidence: high

```yaml
title: OPTIMJACK Supply Chain Attack - C2 Domain Access via Proxy
id: 7a3e1f8d-2b4c-4d5e-9f6a-1c8b0d7e3f2a
status: experimental
description: >
    Detects web proxy requests to known OPTIMJACK command-and-control domains
    used in the Optimizely Web Experimentation supply chain attack on November
    16 2026. The domains hosted the crypto-clipper payload (track.js), card
    skimming exfiltration (card.php), cookie and screenshot theft (hit.php),
    and iOS exploit kit routers.
references:
    - https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
    - https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
    - https://krebsonsecurity.com/2026/11/attackers-used-optimizely-to-a-b-test-malware-on-top-websites/
author: Actioner
date: 2026/11/21
tags:
    - attack.t1195.002
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_domain:
        c-uri|contains:
            - '1688360.cc'
            - 'webshell.lol'
            - '5vobauua3ojpklx.icu'
            - 'eil786npto9u5bq.icu'
            - 'l7bcsnwc7nzr3uo.icu'
            - 'je4ft3gn8vxudum.icu'
            - 'q1ls1ho9x7wsxlu.icu'
            - 'ios-hack.icu'
            - 'p55abnw2pnsz0bo.icu'
            - '1y69gy2mdzaltz1.icu'
            - 'gm38duxoihbmy5o.icu'
            - 'linkforge.cc'
    condition: selection_domain
falsepositives:
    - Unlikely given the specificity of these attacker-registered domains
level: critical
```

<!-- audit: validated via sigma convert --without-pipeline -t splunk (pass) and -t log_scale (pass). sigma check failed due to MITRE ATT&CK data fetch blocked by proxy (environment issue, not rule issue). Values are real (not defanged) per logsource-encoding spec. All 12 domains confirmed from Unit42, Report URI, and THN sources. -->

### Sigma: OPTIMJACK C2 DNS Query Detection

Detects DNS queries to known OPTIMJACK domains via Sysmon EventID 22 or equivalent DNS logging.

compile: splunk pass, log_scale pass | confidence: high

```yaml
title: OPTIMJACK Supply Chain Attack - DNS Query to C2 Domain
id: 8b4f2e9c-3c5d-4e6f-a07b-2d9c1e8f4a3b
status: experimental
description: >
    Detects DNS queries to known OPTIMJACK command-and-control domains
    associated with the Optimizely supply chain attack. These domains served
    the malicious track.js payload, card skimming exfiltration endpoints, and
    iOS exploit kit infrastructure.
references:
    - https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
    - https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
author: Actioner
date: 2026/11/21
tags:
    - attack.t1195.002
    - attack.t1071.001
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
            - 'q1ls1ho9x7wsxlu.icu'
            - 'ios-hack.icu'
            - 'p55abnw2pnsz0bo.icu'
            - '1y69gy2mdzaltz1.icu'
            - 'gm38duxoihbmy5o.icu'
            - 'linkforge.cc'
    condition: selection
falsepositives:
    - Unlikely given the specificity of these attacker-registered domains
level: critical
```

<!-- audit: validated via sigma convert --without-pipeline -t splunk (pass) and -t log_scale (pass). Uses endswith modifier for proper subdomain matching. All domains confirmed from primary sources. -->

### Sigma: OPTIMJACK Card Skimmer Exfiltration URI Paths

Detects HTTP requests combining the primary C2 domain with specific exfiltration and payload delivery paths.

compile: splunk pass, log_scale pass | confidence: high

```yaml
title: OPTIMJACK Supply Chain Attack - Card Skimmer Exfiltration URI Paths
id: 9c5a3f0d-4d6e-4f7a-b18c-3e0d2f9a5b4c
status: experimental
description: >
    Detects HTTP requests to the specific URI paths used by OPTIMJACK for card
    data exfiltration (card.php) and cookie/screenshot theft (hit.php) on the
    primary C2 domain 1688360.cc. These paths received stolen payment card
    numbers and browser session data via navigator.sendBeacon POST requests.
references:
    - https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
    - https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
author: Actioner
date: 2026/11/21
tags:
    - attack.t1056.003
    - attack.t1041
logsource:
    category: proxy
detection:
    selection_domain:
        c-uri|contains: '1688360.cc'
    selection_paths:
        c-uri|contains:
            - '/card.php'
            - '/hit.php'
            - '/track.js'
    condition: selection_domain and selection_paths
falsepositives:
    - Unlikely given the combination of a known malicious domain and specific exfiltration paths
level: critical
```

<!-- audit: validated via sigma convert --without-pipeline -t splunk (pass) and -t log_scale (pass). AND condition between domain and path reduces false positives to near zero. -->

### YARA: OPTIMJACK track.js Payload Detection

Detects the malicious track.js JavaScript payload based on global markers, C2 endpoints, attacker wallet addresses, and behavioral patterns.

compile: yarac pass | confidence: high

```yara
rule Supply_Chain_OPTIMJACK_TrackJS
{
    meta:
        description = "Detects OPTIMJACK malicious JavaScript payload (track.js) used in the Optimizely supply chain attack. Matches crypto-clipper markers, card skimming patterns, and exfiltration endpoints."
        author = "Actioner"
        date = "2026-11-21"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        hash = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"
        hash2 = "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $marker1 = "window._k7" ascii
        $marker2 = "window.__k7b" ascii
        $c2_domain = "1688360.cc" ascii
        $exfil_card = "/card.php" ascii
        $exfil_hit = "/hit.php" ascii
        $track_path = "/track.js" ascii
        $channel = "02111110" ascii
        $coruna_marker = "BIGNIAO" ascii
        $wallet_btc = "19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW" ascii
        $wallet_eth = "0xC4026b06D82b0F0B363eda0642D61CfbDc17884e" ascii
        $wallet_tron = "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa" ascii
        $wallet_sol = "FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n" ascii
        $icu_domain1 = "5vobauua3ojpklx.icu" ascii
        $icu_domain2 = "eil786npto9u5bq.icu" ascii
        $skimmer_fn = "sendBeacon" ascii
        $swap_keyword1 = "wallet" ascii nocase
        $swap_keyword2 = "deposit" ascii nocase
        $obfuscation = "atob(" ascii

    condition:
        filesize < 2MB and
        (
            ($c2_domain and 2 of ($exfil_card, $exfil_hit, $track_path)) or
            (2 of ($marker1, $marker2, $channel, $coruna_marker)) or
            (any of ($wallet_*) and $skimmer_fn) or
            ($c2_domain and any of ($wallet_*)) or
            (any of ($icu_domain*) and $obfuscation) or
            ($skimmer_fn and any of ($swap_keyword*) and any of ($wallet_*))
        )
}
```

<!-- audit: validated via yarac (exit 0). Condition uses multiple OR branches to catch different payload variants. Wallet addresses are specific enough to avoid false positives. The sendBeacon + wallet combo branch is broader but still anchored to attacker-specific wallet strings. -->

### YARA: OPTIMJACK Injector Code Detection

Detects the OPTIMJACK injector code planted in Optimizely Project JavaScript fields, including loader patterns and obfuscated variants.

compile: yarac pass | confidence: high

```yara
rule Supply_Chain_OPTIMJACK_Injector
{
    meta:
        description = "Detects OPTIMJACK injector code planted in Optimizely Project JavaScript fields. Matches loader patterns that dynamically create script elements pointing to attacker C2 or use base64-encoded URLs with eval fallback."
        author = "Actioner"
        date = "2026-11-21"
        reference = "https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/"
        hash = "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $c2_plain = "1688360.cc/track.js" ascii
        $c2_domain = "1688360.cc" ascii
        $injector_domain = "webshell.lol" ascii
        $injector_path = "webshell.lol/get.js" ascii
        $dynamic_script1 = "createElement" ascii
        $dynamic_script2 = "document.head" ascii
        $obfuscation1 = "atob(" ascii
        $eval_fallback = "eval(" ascii
        $marker1 = "window._k7" ascii
        $marker2 = "window.__k7b" ascii
        $linkforge = "linkforge.cc" ascii

    condition:
        filesize < 5MB and
        (
            $c2_plain or
            $injector_path or
            ($c2_domain and $dynamic_script1 and $dynamic_script2) or
            ($injector_domain and $dynamic_script1) or
            ($obfuscation1 and $eval_fallback and any of ($marker*)) or
            ($linkforge and $dynamic_script1)
        )
}
```

<!-- audit: validated via yarac (exit 0). The $c2_plain branch catches plaintext loader (version 1). The $obfuscation1 + $eval_fallback + marker branch catches version 2/3 variants. The injector_domain and linkforge branches catch the earlier wave. -->

### Suricata: OPTIMJACK Network Detection (8 rules)

Eight Suricata rules detecting HTTP exfiltration to the primary C2 and DNS queries to all known OPTIMJACK infrastructure domains.

compile: suricata -T pass | confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK Card Skimmer Exfiltration to 1688360.cc/card.php"; flow:established,to_server; http.host; content:"1688360.cc"; http.uri; content:"/card.php"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-21; sid:2100101; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK Cookie and Screenshot Theft to 1688360.cc/hit.php"; flow:established,to_server; http.host; content:"1688360.cc"; http.uri; content:"/hit.php"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-21; sid:2100102; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK Malicious Payload Delivery track.js from 1688360.cc"; flow:established,to_server; http.host; content:"1688360.cc"; http.uri; content:"/track.js"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-21; sid:2100103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to Primary C2 Domain 1688360.cc"; dns.query; content:"1688360.cc"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-21; sid:2100104; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to iOS Exploit Router 5vobauua3ojpklx.icu"; dns.query; content:"5vobauua3ojpklx.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-21; sid:2100105; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to iOS Exploit Router eil786npto9u5bq.icu"; dns.query; content:"eil786npto9u5bq.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-21; sid:2100106; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to Injector Domain webshell.lol"; dns.query; content:"webshell.lol"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/; metadata:author Actioner, created_at 2026-11-21; sid:2100107; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to Coruna Telemetry Domain l7bcsnwc7nzr3uo.icu"; dns.query; content:"l7bcsnwc7nzr3uo.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-21; sid:2100108; rev:1;)
```

<!-- audit: validated via suricata -T -S (exit 0, "Configuration provided was successfully loaded"). All rules use dot-notation sticky buffers (http.host, http.uri, dns.query). HTTP rules use host+uri combination for precision. DNS rules cover primary C2, iOS routers, injector, and telemetry domains. -->

### Snort 3: OPTIMJACK HTTP Exfiltration Detection (3 rules)

Three Snort 3 rules detecting HTTP traffic to the primary C2 domain's exfiltration and payload delivery endpoints.

compile: snort -T pass | confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK Card Skimmer Exfiltration to 1688360.cc/card.php"; flow:established, to_server; http_header; content:"1688360.cc"; http_uri; content:"/card.php", fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created 2026-11-21; sid:2100201; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK Cookie and Screenshot Theft to 1688360.cc/hit.php"; flow:established, to_server; http_header; content:"1688360.cc"; http_uri; content:"/hit.php", fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created 2026-11-21; sid:2100202; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK Malicious Payload Delivery track.js from 1688360.cc"; flow:established, to_server; http_header; content:"1688360.cc"; http_uri; content:"/track.js", fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created 2026-11-21; sid:2100203; rev:1;)
```

<!-- audit: validated via snort -c /etc/snort/snort.conf -R test.rules -T (exit 0, "Snort successfully validated the configuration"). Uses underscore buffers (http_header, http_uri) per Snort 3 syntax. Host matching via http_header buffer for the domain, combined with http_uri for the specific path. -->

## Lessons Learned

1. **Trusted CDN is not trusted code.** The Optimizely snippet was served from a legitimate CDN with a valid certificate, yet carried attacker-controlled JavaScript. Organizations must move beyond domain-based trust and implement content integrity verification (SRI hashes, continuous content monitoring) for all third-party scripts.

2. **CSP is necessary but insufficient against supply chain attacks.** Only 15% of affected sites had CSPs restrictive enough to block the payload. Sites using `'strict-dynamic'` or `'unsafe-eval'` (the latter recommended by Optimizely's own documentation) were fully compromised. CSPs must be paired with tight `connect-src` directives to block exfiltration even when script execution cannot be prevented.

3. **Third-party JavaScript with pre-consent execution is a systemic risk.** The Optimizely snippet fires before any user consent mechanism, giving the attacker access to every visitor. Organizations should audit all third-party scripts for execution timing and minimize the number of scripts with page-load execution privileges.

4. **Payment isolation is the strongest defense against web skimmers.** Sites using cross-origin iframes for payment processing (Stripe Hosted Fields, Adyen) were protected from card theft even when the page-level JavaScript was compromised. This architectural pattern should be standard for all e-commerce implementations.

5. **Supply chain attacks can combine multiple threat categories.** OPTIMJACK simultaneously performed financial theft (card skimming + crypto clipping), session hijacking, and zero-day iOS exploitation -- demonstrating that a single supply chain compromise can serve as a platform for diverse, escalating attacks within hours.

## Sources

- [Palo Alto Networks Unit 42 - OPTIMJACK Supply Chain Attack](https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/) -- primary technical analysis of attack methodology, payload behavior, and timeline
- [Krebs on Security - Attackers Used Optimizely to A/B Test Malware on Top Websites](https://krebsonsecurity.com/2026/11/attackers-used-optimizely-to-a-b-test-malware-on-top-websites/) -- investigative reporting on scope, CSP analysis, and Optimizely remediation
- [The Hacker News - Hijacked Optimizely Scripts Served Card Skimmers](https://thehackernews.com/2026/11/hijacked-optimizely-scripts-served-card.html) -- technical details on loader variants, IOCs, iOS exploit kits, and code patterns
- [Report URI - World's Largest Brands Infected with Malware via Optimizely](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/) -- comprehensive IOC list, cryptocurrency wallet addresses, affected organization enumeration, CSP effectiveness analysis, and detailed timeline

---
*Report generated by Actioner*
