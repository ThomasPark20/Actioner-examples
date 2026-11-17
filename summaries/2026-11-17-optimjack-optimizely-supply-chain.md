# Technical Analysis Report: OPTIMJACK -- Optimizely Script Hijacking Supply Chain Attack (2026-11-17)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-17
Version: 1.1

## Executive Summary

On 16 November 2026, an attacker exploited a vulnerability in the Optimizely Web Experimentation platform to inject malicious JavaScript into the Project JavaScript field of customer projects. The tampered scripts were served from Optimizely's own CDN (`cdn.optimizely.com`) with valid certificates, making them appear trusted. Report URI identified 188 infected snippets across 178 organizations, including BBC, CNN, Zoom, GitLab, Salesforce, HSBC, Equifax, IKEA, and Air France-KLM. The injected payload -- dubbed OPTIMJACK -- performs cryptocurrency wallet address swapping (covering BTC, ETH, TRON, Solana, TON, LTC, BCH, and DOGE), payment card skimming via form interception, cookie and screenshot exfiltration, and delivers iOS exploit kits (Coruna and DarkSword) to mobile visitors. The exposure window was approximately 16 hours (04:21 to ~21:00 UTC on 16 November). Financial impact was modest at approximately $7,040 in cryptocurrency received by attacker wallets within that window, though card theft and cookie exfiltration volumes are unknown. Optimizely issued an incident notice at 01:02 UTC on 17 November confirming they fixed the vulnerability and cleaned affected projects. No CVE has been assigned.

## Background: Optimizely Web Experimentation

Optimizely Web Experimentation is a widely deployed A/B testing and digital experience optimization platform. Organizations embed a per-project JavaScript snippet from `cdn.optimizely.com` that runs on every page load to deliver experiments and personalization. The snippet includes an optional **Project JavaScript** (`projectJS`) field intended for a customer's own code. This field executes in the same origin context as the host page, giving it full access to page content, cookies, and network requests. Some customers self-host the snippet on their own domains, but the content still originates from the same Optimizely project. Optimizely's own documentation recommends `'unsafe-eval'` in Content Security Policy configurations, which weakened one layer of defense for many deployments.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-09-17 | `webshell[.]lol` injector first appears on Turkish sites via SEO backlink panel script |
| 2026-11-09 | `5vobauua3ojpklx[.]icu` registered (iOS exploit router) |
| 2026-11-13 to 2026-11-16 | Earlier wave: `webshell[.]lol/get.js` injected via Kissmetrics, StorifyMe, and Minute Media scripts |
| 2026-11-16 02:21 | Last clean capture of BBC's Optimizely snippet |
| 2026-11-16 04:21 | First Optimizely injection observed (BBC snippet loading `webshell[.]lol`) |
| 2026-11-16 04:28-05:23 | TLS certificates issued for `1688360[.]cc`; domain registered at 05:23 |
| 2026-11-16 08:10 | First `track.js` build (crypto clipper functionality) |
| 2026-11-16 08:28 | `track.js` first observed live on bbc.com |
| 2026-11-16 11:20 | Zoom snippet modified (per Last-Modified header) |
| 2026-11-16 13:03 | Stolen cryptocurrency swept to exchanges |
| 2026-11-16 13:43 | Card skimmer functionality added to `track.js` |
| 2026-11-16 16:38 | `eil786npto9u5bq[.]icu` registered (second iOS router) |
| 2026-11-16 17:13-17:57 | iOS exploit delivery activated; Coruna iframe injected for iOS 18.6 and earlier |
| 2026-11-16 19:24-19:59 | Report URI sweep: 186 of 1,611 snippets infected |
| 2026-11-16 ~20:40-21:10 | Mass cleanup begins (Ledger, Smartsheet, BBC) |
| 2026-11-16 21:52 | Only 1 of 188 infected snippets remains (TalkTalk) |
| 2026-11-16 23:11 | All infected Optimizely files cleaned |
| 2026-11-17 00:37 | `1688360[.]cc` placed on clientHold (no longer resolves) |
| 2026-11-17 01:02 | Optimizely posts incident notice on status page |
| 2026-11-17 03:37 | `webshell[.]lol` placed on clientHold |

## Root Cause: Optimizely Platform Vulnerability

Optimizely confirmed that "an unauthorized party exploited a vulnerability in Experimentation" to add malicious JavaScript to customer projects. The exact nature of the vulnerability has not been disclosed. Report URI's analysis found that the attacker gained write access to the **Project JavaScript** field across many unrelated customer projects -- the injection point was not CDN cache poisoning. StepSecurity noted the vulnerability may have been in the account signup flow. The attacker retained access long enough to re-infect Smartsheet's snippet with an obfuscated variant after initial cleanup, demonstrating persistent access. Optimizely stated it fixed the flaw, removed injected code, secured affected accounts, and added protections. A separate February 2026 incident involving voice-phishing access to Optimizely systems was also disclosed.

## Technical Analysis of the Malicious Payload

### 1. Injection and Loader Delivery

The attacker injected loader code into each customer's Project JavaScript field. The rest of each Optimizely snippet was left untouched. Three loader variants were observed:

**Variant 1 -- Plain script tag (most common):** Creates a `<script>` element pointing to `hxxps://1688360[.]cc/track.js` and appends it to the document head.

**Variant 2 -- Base64-obfuscated:** The C2 URL is base64-encoded and decoded at runtime with `atob()`. A plain-text search for `1688360.cc` will not find this variant. Smartsheet was re-infected with this form after initial cleanup.

**Variant 3 -- Inline full payload (eval fallback):** Contains a complete 24,392-byte copy of the payload encoded in Base64 that runs via `eval` if the external domain is blocked. This was observed at HSBC's snippet. A 2.5-second timeout triggers fallback to the embedded copy, with additional retry via `fetch` and `XMLHttpRequest`.

The payload was rebuilt 26 times on 16 November. The server sent `cache-control: max-age=15`, allowing the operator to swap files within seconds.

### 2. Crypto Wallet Address Swapper

The primary payload function replaces cryptocurrency wallet addresses across the page:

- **Targeted chains:** Bitcoin, Ethereum/EVM, TRON, Solana, TON, Litecoin, Bitcoin Cash, and Dogecoin
- **Surfaces rewritten:** Page text, form input values, link/image attributes, clipboard (via copy event and Clipboard API), `navigator.share`, `fetch`/XHR request URLs and bodies, `window.open`, and navigation/history APIs
- **Validation:** Only swaps addresses that pass each chain's checksum validation and appear near payment-related terms ("wallet," "deposit," "send")
- **Persistence:** Hooks `Function.prototype.call` and `apply` to rewrite wallet-like strings before they reach any function; re-scans on DOM changes via MutationObserver; runs a 50ms scan interval while the page is visible
- **No seed/key theft:** No wallet-signing or seed extraction was identified

### 3. Card Skimmer

Added at 13:43 UTC on 16 November:

- Wraps `fetch`, `XMLHttpRequest`, and form submit events
- Validates card numbers with Luhn check and known brand prefixes
- Requires valid expiry date and 3-4 digit CVV/CVC
- Sends captured data (`n`=card number, `e`=expiry, `c`=CVV, `u`=page URL) to `/card.php` via `navigator.sendBeacon`
- Cannot read cross-origin payment iframes (e.g., Stripe Hosted Fields, Adyen)
- Stores captured cards in `sessionStorage` under keys prefixed `cc_` to prevent duplicate sends (leaving card data in browser storage)

### 4. Cookie and Screenshot Exfiltration

Triggered once per page after a successful address swap near payment-related text:

- Loads `html2canvas.min.js` from the C2 server
- Captures page as JPEG screenshot
- POSTs to `/hit.php` with: page URL (up to 500 chars), `document.cookie` (up to 8,000 chars), recorded original addresses (up to 20), and the screenshot
- HttpOnly cookies are not accessible

### 5. C2 Infrastructure

| Component | Domain/IP | Role |
|-----------|-----------|------|
| Primary C2 | `1688360[.]cc` (136[.]113[.]106[.]136, Google Cloud us-central1) | Payload host, card exfil, cookie/screenshot exfil |
| Injector | `webshell[.]lol` | Earlier-wave injector `get.js` |
| iOS router 1 | `5vobauua3ojpklx[.]icu` (34[.]96[.]213[.]201, Google Cloud HK) | `boot.js`, DarkSword entry |
| iOS router 2 | `eil786npto9u5bq[.]icu` (34[.]87[.]36[.]58, Google Cloud SG) | `boot.js`, Coruna entry, iOS 26 |
| Telemetry | `l7bcsnwc7nzr3uo[.]icu` (behind Cloudflare) | Coruna telemetry, `POST /api/iptj` |
| Fallback C2 | `je4ft3gn8vxudum[.]icu` | Hard-coded in `boot.js` |
| Fallback C2 | `ios-hack[.]icu` | IP-sync endpoint |
| Fallback | `q1ls1ho9x7wsxlu[.]icu` (behind Cloudflare) | Additional iOS infrastructure |
| SEO panel | `linkforge[.]cc` | Carried the initial injector script |
| Shared infra | `p55abnw2pnsz0bo[.]icu`, `1y69gy2mdzaltz1[.]icu`, `gm38duxoihbmy5o[.]icu` | Share certificates/IPs with the kit |

URL paths observed: `/track.js`, `/card.php`, `/hit.php`, `/html2canvas.min.js`, `/px.gif`, `/boot.js`, `/JIUJIU888/weifile.html`, `/JIUJIU888/index.js`, `/A8/a.html`, `/D11/b.html`, `/D12/b.html`, `/C10/b.html`, `/api/track`, `/api/gs_state`, `/api/pe_ok`, `/chain_log`

### 6. iOS Exploit Delivery

For iPhone, iPad, and iPod user agents, the payload loads `boot.js` from the `.icu` domains with channel code `02111110` and routes by iOS version:

| iOS Version | Chain | Entry Path |
|-------------|-------|------------|
| 13-17 | Coruna | `/A8/a.html`, `/JIUJIU888/index.js` |
| 18.x | DarkSword | `/D11/b.html`, `/D12/b.html` |
| 26 | Separate (fingerprinting only) | `/C10/b.html` |

- Pages on iOS 18.6 or earlier reload every 60 seconds to retry the exploit (a visible symptom)
- Kit comments indicate iOS 18.7.3+ and 26.3+ are patched
- The Coruna loader is byte-identical to a sample analyzed in October from a different campaign
- **No confirmed successful device exploitation** -- evidence shows delivery and routing, not confirmed compromise
- XOR-encoded C2 strings decoded with key `d7K9mP2x`; once-per-24-hour frame gate; 30-minute pause after two failures

### 7. Anti-Forensics / Evasion Techniques

- Base64 encoding of C2 URL in loader variant 2
- Inline `eval` fallback ensures execution even if C2 domain is blocked
- `Function.prototype.call`/`apply` hooking to intercept wallet strings transparently
- 15-second cache lifetime enables rapid payload rotation (26 rebuilds in one day)
- Self-cleanup in Minute-ly loader variant (removes script elements after 3 seconds)
- Re-infection of cleaned snippets (Smartsheet) with obfuscated variant

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1[.]2[.]3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Optimizely Web Experimentation (Project JavaScript) | Multiple customer projects | Attacker-injected loader code in projectJS field |
| Kissmetrics (`i[.]kissmetrics[.]com/i.js`) | Compromised | Earlier-wave injection vector |
| StorifyMe (`cdn[.]storifyme[.]com` / `storifyme[.]xyz`) | Compromised widgets | Earlier-wave injection vector |
| Minute Media (`apv-static[.]minute-ly[.]com`) | Compromised loader | Earlier-wave injection vector |

### File System

| Platform | Path/File | Hash (SHA256) | Description |
|----------|-----------|---------------|-------------|
| Web | `track.js` (final, 17:56 build) | f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40 | Final payload (crypto clipper + card skimmer + exfil) |
| Web | `track.js` (earliest, ~08:10) | 617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3 | First payload build |
| Web | `track.js` (17:13 build) | 814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f | Intermediate build |
| Web | `track.js` (16:17 scan) | 450794992ffe035dce462ef669c6ac46e1a9e87b7b0af3e8f9040f9436cd896f | Intermediate build |
| Web | Embedded payload (decoded, 24,392 B) | c2a34c579e4c2e8802752c93b3a9cca0230610f3e4dd6688f4272459c7c7c162 | Inline eval fallback payload |
| Web | `webshell[.]lol/get.js` | 123f813b18cf5a3b513beabd52a110e19f1c7834f2aa9b972633b2214c57e737 | Injector script |
| Web | `5vobauua3ojpklx[.]icu/boot.js` | 8d69f32fff37208e52dc573111e8db99f031f4913845a24fb2e14755747ac860 | iOS router script |
| Web | `eil786npto9u5bq[.]icu/boot.js` | e410b6509f33defce16ad7896cbe2fb3cc689f2cc53d87c87d75efba6b57e290 | iOS router script |
| Web | `minute-ly loader` (561 B) | 0f2f2a27d19112e5800541daecc91eb6c77e49f9b43ed23c890b876631978533 | Minute-ly vector |
| Web | `JIUJIU888/weifile.html` | f286c965982bee4225c4edda261ce8685a55721dd997ddedf106666101118c07 | Coruna entry |
| Web | `JIUJIU888/index.js` | 435987c1d7f4da3d4a6d3175538d32751d1a6d55a38dcc9d39c24399a8eaa6fa | Coruna loader |
| Web | `A8/a.html` | 9039ebbdd6abe36ad8ac48097dae6813d4a49315e1403c9ae7ebab539601cde6 | Coruna entry |
| Web | `D11/b.html` | 792deb03483ce9b212df6f46319a78ea6fc39bfc5b2719c7e8b87d084524437d | DarkSword entry |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `1688360[.]cc` | Primary C2: payload, card exfil, cookie/screenshot exfil |
| Domain | `webshell[.]lol` | Injector, earlier-wave |
| Domain | `5vobauua3ojpklx[.]icu` | iOS exploit router 1 |
| Domain | `eil786npto9u5bq[.]icu` | iOS exploit router 2 |
| Domain | `l7bcsnwc7nzr3uo[.]icu` | Coruna telemetry |
| Domain | `je4ft3gn8vxudum[.]icu` | Fallback C2 (decoded from boot.js) |
| Domain | `ios-hack[.]icu` | IP-sync endpoint |
| Domain | `q1ls1ho9x7wsxlu[.]icu` | Additional iOS infrastructure |
| Domain | `p55abnw2pnsz0bo[.]icu` | Shared infrastructure |
| Domain | `1y69gy2mdzaltz1[.]icu` | Shared infrastructure |
| Domain | `gm38duxoihbmy5o[.]icu` | Shared infrastructure |
| Domain | `linkforge[.]cc` | SEO panel carrying injector |
| IP | 136[.]113[.]106[.]136 | Hosted `1688360[.]cc` (Google Cloud, us-central1) |
| IP | 34[.]96[.]213[.]201 | Hosted `.icu` batch (Google Cloud, Hong Kong) |
| IP | 34[.]87[.]36[.]58 | Hosted `.icu` batch (Google Cloud, Singapore) |
| URL | `hxxps://1688360[.]cc/track.js` | Crypto clipper + card skimmer payload |
| URL | `hxxps://1688360[.]cc/card.php` | Card data exfiltration endpoint |
| URL | `hxxps://1688360[.]cc/hit.php` | Cookie/screenshot exfiltration endpoint |
| URL | `hxxps://1688360[.]cc/html2canvas.min.js` | Screenshot library loaded by payload |
| SSH Key | `5e:7a:7f:b3:d7:22:ba:c7:f5:04:5a:b2:5c:0d:8a:73` | ed25519 host key (useful for pivoting) |

### Cryptocurrency Wallet Addresses (Attacker)

| Chain | Address | Received (16 Nov) |
|-------|---------|-------------------|
| BTC | `19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW` | ~0.08298 BTC (~$5,380) |
| ETH/EVM | `0xC4026b06D82b0F0B363eda0642D61CfbDc17884e` | ~0.055 ETH (~$100) + 82 USDT (BSC) |
| LTC | `ltc1q3wp7g6ds0ggg6fl6kncpa4sepn0q3qfacgred5` | ~17.02 LTC (~$762) |
| TRON | `THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa` | ~662.9 USDT + 184 TRX (~$719) |
| SOL | `FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n` | Unknown |
| TON | `UQAgM1VqSZQiJLSG5w-ovurq5CZdxLEK3_7CMmwALTA5e09p` | Unknown |
| BCH | `qzkaaf8n6grmpr0d9lx8xutn3r9lk722f566hhpe58` | Unknown |
| DOGE | `DBEGrxRF7KMSuhTS4c1MFviStU6efdMnu5` | Unknown |

TRON wallet `TMLQvDvpgSyx94maptc3TxvmCVtT5qHVup` was used for cash-outs in March and 3 November 2026, linking to other operations.

### Behavioral

- **JavaScript globals set by payload:** `window._k7`, `window.__k7b`, `window._cc`, `window._shot`, `window._qxc`
- **sessionStorage keys:** Prefixed with `cc_` (card skimmer dedup)
- **Non-native `Function.prototype.call` and `Function.prototype.apply`** (hooking indicator)
- **iOS markers:** `channelCode`/`data-channel-code` = `02111110`; visitor key prefix `ds_`; storage key `ds_vk`; config object `__DAILI_CFG`; hidden 320x568 frame `chainFrame` with `data-daili-gate="v1"`; dispatcher `globalThis.obChTK`; Base64 map marker `let MM=`
- **XOR key:** `d7K9mP2x` (used for C2 string encoding in boot.js)
- **Page reload:** 60-second reload cycle on iOS 18.6 or earlier (visible symptom)
- **Detection strings:** `1688360`, `atob(`, `track.js`, `.icu`, `BIGNIAO` (Coruna telemetry channel code)

<!-- revision: replaced T1204.001 (User Execution) with T1565.002 (Transmitted Data Manipulation) for address swapping; replaced T1005 (Data from Local System) with T1113 (Screen Capture) for screenshot component -->
## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attacker injected malicious code into Optimizely customer projects, served via trusted CDN |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Payload executes as JavaScript in visitor browsers |
| T1185 | Browser Session Hijacking | Hooks Function.prototype.call/apply, clipboard, fetch, XHR to intercept and modify browser sessions |
| T1056.003 | Input Capture: Web Portal Capture | Card skimmer captures card number, expiry, CVV from form submissions |
| T1115 | Clipboard Data | Hooks clipboard and copy events to swap wallet addresses |
| T1113 | Screen Capture | Captures page screenshot via html2canvas and exfiltrates it along with document.cookie to /hit.php |
| T1041 | Exfiltration Over C2 Channel | Card data to /card.php, cookies/screenshots to /hit.php via sendBeacon/POST |
| T1027 | Obfuscated Files or Information | Base64-encoded loader URL, XOR-encoded C2 strings, inline eval fallback |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication over HTTPS |
| T1565.002 | Data Manipulation: Transmitted Data Manipulation | Crypto address replacement modifies wallet addresses in transit (page content, clipboard, fetch/XHR bodies) to redirect funds to attacker wallets |
| T1203 | Exploitation for Client Execution | iOS exploit kits (Coruna, DarkSword) delivered to mobile visitors |
| T1587.001 | Develop Capabilities: Malware | Custom multi-function payload (clipper, skimmer, screenshotter, iOS router) |

## Impact Assessment

- **Breadth:** 178 organizations affected across 20+ sectors; notable victims include major media (BBC, CNN, Fox News), financial institutions (HSBC, Equifax), technology companies (Zoom, GitLab, Salesforce), and cryptocurrency companies (Ledger)
- **Depth:** Full client-side code execution in visitor browsers; card data, cookies, screenshots exfiltrated; cryptocurrency transactions redirected to attacker wallets; iOS exploit kits served
- **Stealth:** Payload served from trusted Optimizely CDN with valid certificates; base64 obfuscation evaded simple text searches; inline fallback evaded domain blocking; 15-second cache lifetime enabled rapid evolution
- **Financial:** ~$7,040 in confirmed cryptocurrency received within ~9 hours; card theft volumes unknown; potential iOS exploitation unconfirmed
- **CSP analysis (256 hosts):** 68 had no CSP; 50 allowed payload and exfiltration; 17 blocked exfil but not address swapping; only 24 (15%) fully blocked the payload

## Detection & Remediation

### Immediate Detection

<!-- revision: added defanging exception note for detection query blocks -->
> **Note:** Indicators in the search query blocks below appear without defanging (e.g., `1688360.cc` not `1688360[.]cc`) so they can be copied directly into search tools. Un-defang the IOC table entries before using them in queries, or use the literal forms shown here.

Search Optimizely Project JavaScript and experiment custom code for:
```
1688360
atob(
webshell.lol
track.js (in unexpected contexts)
window._k7
02111110
```

Search proxy/firewall logs for connections to:
```
1688360.cc
webshell.lol
*.icu (specifically the IOC domains listed above)
136.113.106.136
34.96.213.201
34.87.36.58
```

Search browser telemetry for:
```
sessionStorage keys prefixed with cc_
Non-native Function.prototype.call or Function.prototype.apply
```

### Remediation

1. **Audit all Optimizely projects:** Check every Project JavaScript field and experiment custom code for injected content
2. **Rotate credentials:** Reset passwords, API tokens, and integrations for all users with Optimizely project access
3. **Treat card entries as exposed:** Any card data entered on affected sites' own forms between 13:43 and ~21:00 UTC on 16 November should be considered compromised; notify payment processor
4. **Rotate cookie secrets:** Invalidate sessions and rotate secrets for non-HttpOnly cookies
5. **Verify cryptocurrency transactions:** Any wallet addresses displayed on affected pages during the exposure window may have been swapped
6. **Update iOS devices:** Ensure iOS 18.7.3+ or 26.3+ to mitigate Coruna/DarkSword exploit chains (these version thresholds are derived from comments in the exploit kit code; verify against Apple's official security updates at https://support.apple.com/en-us/100100 before treating as authoritative)
7. **Contact Optimizely:** Request confirmation of which project IDs were modified

### Long-Term Hardening

1. **Deploy restrictive CSP:** Implement `script-src` and `connect-src` policies that explicitly allowlist only needed hosts; avoid `'unsafe-eval'` and `'strict-dynamic'` where possible
2. **Enable CSP reporting:** Monitor for blocked requests indicating injection attempts
3. **Use Subresource Integrity (SRI):** Where feasible, pin hashes of third-party scripts (note: dynamically generated scripts like Optimizely's resist SRI)
4. **Isolate payment pages:** Remove all third-party tags from checkout and payment pages
5. **Monitor third-party script behavior:** Use script monitoring services (Report URI, etc.) to detect unauthorized changes to loaded scripts
6. **Implement hardware wallet verification:** For cryptocurrency operations, verify addresses on the hardware wallet screen, not the browser

## Detection Rules

These detections target IOCs from the OPTIMJACK Optimizely supply chain attack at PoC/advisory-specific altitude. Sigma rules convert cleanly to Splunk and CrowdStrike LogScale. `sigma check` was run with `-x attacktag` because the MITRE ATT&CK data endpoint was unreachable from this environment; the ATT&CK tags used (`attack.t1071.001`, `attack.t1195.002`) are valid technique IDs. Compiles does not equal fires -- verify each rule against your pipeline telemetry.

### Sigma: OPTIMJACK C2 Domain in Proxy Logs

Detects proxy/web log requests to the OPTIMJACK primary C2 domain `1688360[.]cc`.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check exit 0 (excluding attacktag validator due to network-blocked MITRE data fetch); splunk convert exit 0; log_scale convert exit 0. Domain is attacker-registered (2026-11-16 05:23 UTC) and now on clientHold. No benign use expected. -->
```yaml
title: OPTIMJACK C2 Domain in Proxy Logs
id: 7f3a8b1c-4e2d-4a6f-9c5b-2d1e0f8a3c7b
status: experimental
description: >
    Detects proxy/web log requests to the OPTIMJACK C2 domain 1688360.cc, used to
    serve the crypto clipper, card skimmer, and data exfiltration endpoints (track.js,
    card.php, hit.php) in the Optimizely supply chain attack of November 2026.
references:
    - https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
    - https://thehackernews.com/2026/11/hijacked-optimizely-scripts-served-card.html
    - https://stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer
author: Actioner
date: 2026/11/17
tags:
    - attack.t1071.001
    - attack.t1195.002
logsource:
    category: proxy
detection:
    selection:
        cs-host|contains: '1688360.cc'
    condition: selection
falsepositives:
    - None expected; this is an attacker-registered domain
level: high
```

### Sigma: OPTIMJACK DNS Query to Known Malicious Domains

Detects DNS queries to the 12 domains associated with OPTIMJACK infrastructure (C2, iOS exploit routers, injector, SEO panel).
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check exit 0 (excluding attacktag); splunk convert exit 0; log_scale convert exit 0. All domains are attacker-registered. ios-hack.icu and linkforge.cc are broader but included as they appear only in campaign context. -->
```yaml
title: OPTIMJACK DNS Query to Known Malicious Domains
id: 9e4c2d1f-5b3a-4f8e-a7d6-3c0b1e9f2a5d
status: experimental
description: >
    Detects DNS queries to domains associated with the OPTIMJACK Optimizely supply chain
    attack, including the primary C2 domain, iOS exploit delivery domains, and the
    webshell.lol injector domain.
references:
    - https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
    - https://thehackernews.com/2026/11/hijacked-optimizely-scripts-served-card.html
    - https://stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer
author: Actioner
date: 2026/11/17
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
            - 'ios-hack.icu'
            - 'q1ls1ho9x7wsxlu.icu'
            - 'p55abnw2pnsz0bo.icu'
            - '1y69gy2mdzaltz1.icu'
            - 'gm38duxoihbmy5o.icu'
            - 'linkforge.cc'
    condition: selection
falsepositives:
    - None expected; all are attacker-registered domains
level: high
```

### Sigma: OPTIMJACK Network Connection to C2 IP

Detects outbound connections to 136[.]113[.]106[.]136, which hosted the OPTIMJACK C2 domain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check exit 0 (excluding attacktag); splunk convert exit 0; log_scale convert exit 0. IP is Google Cloud us-central1; may be reassigned -- time-bound to campaign window for production use. -->
```yaml
title: OPTIMJACK Network Connection to C2 IP
id: b2d4e6f8-1a3c-5b7d-9e0f-4c2a6b8d0e1f
status: experimental
description: >
    Detects outbound network connections to the IP address 136.113.106.136, which hosted
    the OPTIMJACK C2 domain 1688360.cc used in the Optimizely supply chain attack.
references:
    - https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
    - https://stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer
author: Actioner
date: 2026/11/17
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '136.113.106.136'
    condition: selection
falsepositives:
    - IP may be reassigned in the future; verify with current DNS resolution
level: high
```

### Snort: OPTIMJACK DNS Queries to C2 Domains

Detects DNS queries to the OPTIMJACK primary C2 domain and key infrastructure domains using DNS label-length encoding.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0 with custom config including classification.config. Snort 2.9.20. DNS label encoding: |07|=7-byte label "1688360", |02|=2-byte "cc", |00|=root; |08|=8-byte "webshell", |03|=3-byte "lol"; |0F|=15-byte "5vobauua3ojpklx", |03|=3-byte "icu". -->
<!-- revision: fixed DNS label length for 5vobauua3ojpklx from |10| (hex 16) to |0F| (hex 15); "5vobauua3ojpklx" is 15 bytes -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - OPTIMJACK DNS Query to C2 Domain 1688360.cc"; flow:to_server; content:"|07|1688360|02|cc|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/; sid:2100001; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"Actioner - OPTIMJACK DNS Query to Injector Domain webshell.lol"; flow:to_server; content:"|08|webshell|03|lol|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/; sid:2100002; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"Actioner - OPTIMJACK DNS Query to iOS Exploit Domain 5vobauua3ojpklx.icu"; flow:to_server; content:"|0F|5vobauua3ojpklx|03|icu|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/; sid:2100003; rev:1;)
```

### Suricata: OPTIMJACK DNS Queries to Malicious Domains

Detects DNS queries to the four key OPTIMJACK domains using Suricata's native `dns.query` buffer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). Uses dns.query sticky buffer with domain content matching. All four domains are attacker-registered and campaign-specific. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to Primary C2 Domain 1688360.cc"; flow:to_server; dns.query; content:"1688360.cc"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/; metadata:author Actioner, created_at 2026-11-17; sid:2200001; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to iOS Exploit Domain (5vobauua3ojpklx.icu)"; flow:to_server; dns.query; content:"5vobauua3ojpklx.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/; metadata:author Actioner, created_at 2026-11-17; sid:2200002; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to iOS Exploit Domain (eil786npto9u5bq.icu)"; flow:to_server; dns.query; content:"eil786npto9u5bq.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/; metadata:author Actioner, created_at 2026-11-17; sid:2200003; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK DNS Query to Injector Domain webshell.lol"; flow:to_server; dns.query; content:"webshell.lol"; nocase; fast_pattern; classtype:trojan-activity; reference:url,blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/; metadata:author Actioner, created_at 2026-11-17; sid:2200004; rev:1;)
```

### Suricata: OPTIMJACK HTTP Requests to C2 Endpoints

Detects HTTP requests to the OPTIMJACK C2 domain's payload and exfiltration endpoints.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). Uses http.host and http.uri sticky buffers. Matches the three observed C2 URL paths: /track.js (payload), /card.php (card exfil), /hit.php (cookie/screenshot exfil). Domain is now on clientHold. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK HTTP Request to track.js Payload on C2 Domain"; flow:established,to_server; http.host; content:"1688360.cc"; fast_pattern; http.uri; content:"/track.js"; classtype:trojan-activity; reference:url,blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/; metadata:author Actioner, created_at 2026-11-17; sid:2200010; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK Card Skimmer Exfiltration to card.php"; flow:established,to_server; http.host; content:"1688360.cc"; http.uri; content:"/card.php"; fast_pattern; classtype:trojan-activity; reference:url,blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/; metadata:author Actioner, created_at 2026-11-17; sid:2200011; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK Cookie and Screenshot Exfiltration to hit.php"; flow:established,to_server; http.host; content:"1688360.cc"; http.uri; content:"/hit.php"; fast_pattern; classtype:trojan-activity; reference:url,blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/; metadata:author Actioner, created_at 2026-11-17; sid:2200012; rev:1;)
```

### YARA: OPTIMJACK track.js Payload Detection

Detects the OPTIMJACK track.js payload via its distinctive JavaScript globals, exfiltration endpoints, and hardcoded attacker wallet addresses.
**Status:** compile ✅ compiles · confidence: high · sample: constructed positive (not a real capture)
<!-- audit: yarac exit 0. Sample test: fired on constructed positive containing published globals (window._k7 etc.), exfil endpoints (/card.php, /hit.php), domain (1688360.cc), and wallet addresses from source IOC table; quiet on benign analytics script. Positive strings are from Report URI and StepSecurity published analysis, not invented. The positive sample was fabricated from published IOCs, not a real malware capture. -->
<!-- revision: relabeled "sample: fired" to "sample: constructed positive (not a real capture)" for honesty about test methodology -->
```yara
rule Supply_Chain_OPTIMJACK_TrackJS_Payload
{
    meta:
        description = "Detects the OPTIMJACK track.js payload via distinctive JavaScript globals, exfiltration endpoints, and crypto clipper markers used in the Optimizely supply chain attack"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/"
        hash = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"
        severity = "critical"

    strings:
        $global1 = "window._k7" ascii
        $global2 = "window.__k7b" ascii
        $global3 = "window._cc" ascii
        $global4 = "window._shot" ascii
        $global5 = "window._qxc" ascii
        $exfil1 = "/card.php" ascii
        $exfil2 = "/hit.php" ascii
        $wallet_btc = "19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW" ascii
        $wallet_eth = "0xC4026b06D82b0F0B363eda0642D61CfbDc17884e" ascii
        $wallet_trx = "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa" ascii
        $domain = "1688360.cc" ascii

    condition:
        filesize < 500KB and
        (
            ($domain and 2 of ($exfil*)) or
            (3 of ($global*)) or
            (2 of ($wallet*) and 1 of ($exfil*))
        )
}
```

### YARA: OPTIMJACK Loader Variant Detection

Detects OPTIMJACK loader variants injected into Optimizely Project JavaScript, including the base64-obfuscated and inline eval forms, and the iOS exploit router markers.
**Status:** compile ✅ compiles · confidence: high · sample: constructed positive (not a real capture)
<!-- audit: yarac exit 0. Sample test: fired on constructed positive containing "1688360.cc/track.js"; quiet on benign. The plain loader string is the most direct indicator; atob+_k7 catches the obfuscated variant; channel code 02111110 + iOS paths catch the mobile router. The positive sample was fabricated from published IOCs, not a real malware capture. -->
<!-- revision: relabeled "sample: fired" to "sample: constructed positive (not a real capture)" for honesty about test methodology -->
```yara
rule Supply_Chain_OPTIMJACK_Loader_Variants
{
    meta:
        description = "Detects OPTIMJACK loader variants injected into Optimizely Project JavaScript, including the base64-obfuscated and inline eval fallback forms"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer"
        severity = "high"

    strings:
        $loader_plain = "1688360.cc/track.js" ascii
        $loader_b64_marker = "atob(" ascii
        $channel = "02111110" ascii
        $ios_path1 = "JIUJIU888" ascii
        $ios_path2 = "boot.js" ascii
        $global_marker = "window._k7" ascii

    condition:
        filesize < 2MB and
        (
            $loader_plain or
            ($loader_b64_marker and $global_marker) or
            ($channel and $ios_path1) or
            ($channel and $ios_path2 and $global_marker)
        )
}
```

## Lessons Learned

1. **Third-party script trust is transitive risk.** When an organization includes a snippet from Optimizely (or any third-party), they implicitly trust not just the vendor but the vendor's entire security posture -- including account management, access controls, and incident response. The Optimizely CDN served the malicious code with valid certificates, making it indistinguishable from legitimate content.

2. **Content Security Policy is necessary but insufficient.** Only 15% of affected organizations' CSP configurations blocked the payload. Policies using `'strict-dynamic'` or `'unsafe-eval'` -- the latter recommended by Optimizely's own documentation -- allowed the malicious code to execute. Effective CSP requires explicit host allowlisting for `script-src` and `connect-src`, which conflicts with the dynamic nature of experimentation platforms.

3. **Supply chain attacks are force multipliers.** A single compromise of one platform feature affected 178 organizations across 20+ sectors within hours. The attacker's modest financial return (~$7,000) belies the enormous potential impact: access to form data, cookies, and browser sessions on sites visited by hundreds of millions of users.

4. **Inline fallbacks defeat domain-based blocking.** The attacker's inclusion of a full payload copy via `eval` meant that blocking the C2 domain alone was insufficient. Defense in depth -- CSP, script monitoring, and behavioral detection -- is essential.

5. **Rapid iteration challenges signature-based detection.** The payload was rebuilt 26 times in one day with 15-second cache lifetimes. Static hash-based detection covers only specific snapshots; behavioral and string-based detection (globals, endpoints, wallet addresses) proved more durable.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Report URI Blog](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/) -- primary technical analysis with full IOC list, timeline, CSP analysis, and affected organization enumeration
- [The Hacker News](https://thehackernews.com/2026/11/hijacked-optimizely-scripts-served-card.html) -- comprehensive summary with payload mechanics, iOS exploit chain details, and financial impact
- [SecurityWeek](https://www.securityweek.com/optimizely-vulnerability-exploited-to-serve-malware-on-major-websites/) -- incident overview with vendor confirmation and scope reporting
- [Hackread](https://hackread.com/optimizely-hack-malware-scripts-178-organisations/) -- coverage citing Report URI and StepSecurity findings
- [Security Affairs](https://securityaffairs.com/203289/malware/optimjack-bbc-cnn-and-zoom-among-targets-of-optimizely-script-hijacking.html) -- detailed technical summary with timeline, CSP findings, and cryptocurrency chain analysis
- [StepSecurity Blog](https://stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer) -- payload deobfuscation, card skimmer code analysis, crypto clipper mechanics, and browser artifact documentation
- [Hudson Rock / Infostealers.com](https://infostealers.com/poisoned-scripts-on-bbc-zoom-and-other-major-websites-linked-to-iphone-exploit-loaders) -- iOS exploit chain analysis, file hashes, infrastructure mapping, and archived vendor response verification
- [Optimizely Status Page](https://status.optimizely.com/incidents/ftw0fh9wx43z) -- vendor incident acknowledgment and remediation confirmation

---
*Report generated by Actioner*
