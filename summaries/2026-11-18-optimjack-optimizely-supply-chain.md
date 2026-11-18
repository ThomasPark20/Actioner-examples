<!-- revision: v1.1 — (1) added missing YARA hash-based rule (SupplyChain_OPTIMJACK_Known_Hashes) using 10 SHA256 hashes from File System IOC table; (2) fixed Snort SIDs 1100001/1100002/1100003/1100005: replaced http_header with http_host for domain-matching content; (3) YARA section now has 3 rules matching its header claim; total rule count 24 is now accurate. -->
# Technical Analysis Report: OPTIMJACK (2026-11-18)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-18
Version: 1.1

## Executive Summary

OPTIMJACK is a supply-chain attack in which an unauthorized actor exploited a vulnerability in Optimizely's Web Experimentation platform signup flow to inject malicious JavaScript into the Project JavaScript fields of customer accounts. Between approximately 04:21 UTC and 23:11 UTC on November 16, 2026, at least 188 Optimizely snippets across 178 organizations — including BBC, CNN, Zoom, HSBC, Equifax, Ledger, and IKEA — served the malicious payload to site visitors via Optimizely's legitimate CDN (`cdn.optimizely.com`). The payload performed cryptocurrency wallet address swapping (crypto clipper) across eight chains, payment card skimming with exfiltration via `navigator.sendBeacon`, cookie and screenshot theft, and routed iOS device visitors into the Coruna (iOS 13-17) and DarkSword (iOS 18.x) exploit kits. Optimizely remediated the vulnerability by November 17, 2026. Confirmed on-chain losses total approximately $7,150 in cryptocurrency; card data and cookie theft volumes remain unknown.

## Background: Optimizely Web Experimentation

Optimizely Web Experimentation is a widely used A/B testing and personalization platform. Customers include a snippet (`cdn.optimizely.com/js/<project_id>.js`) on their websites that loads experiment configurations and custom JavaScript from Optimizely's CDN. The platform includes a "Project JavaScript" field where customers can add custom code that executes on every page load. Some customers self-host the snippet from their own domains (e.g., `opt.scheels.com`, `www.vodafone.com.au`). The snippet is loaded with the same trust level as first-party code, making it an attractive target for supply-chain attacks. Notably, Subresource Integrity (SRI) is impractical for Optimizely snippets because they change whenever experiments are published.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-09-17 | `webshell[.]lol` first seen injecting code on Turkish websites via an SEO backlink panel |
| 2026-10-28 | `l7bcsnwc7nzr3uo[.]icu` registered (Coruna telemetry domain) |
| 2026-11-09 17:52 | `5vobauua3ojpklx[.]icu` and `p55abnw2pnsz0bo[.]icu` registered |
| 2026-11-12 | `/A8/a.html` observed being served from `5vobauua3ojpklx[.]icu` |
| 2026-11-13 to 11-16 | Earlier wave: Kissmetrics, StorifyMe, Minute Media scripts loading `webshell[.]lol/get.js` |
| 2026-11-16 04:21 | First Optimizely injection observed (BBC snippet) via `webshell[.]lol` |
| 2026-11-16 04:28-05:23 | TLS certificates issued for `1688360[.]cc`; domain registered at 05:23 |
| 2026-11-16 08:10 | First `track.js` build observed (crypto clipper functionality) |
| 2026-11-16 11:20 | Zoom Optimizely snippet modified with malicious code |
| 2026-11-16 13:03-13:05 | Stolen crypto funds swept from collector wallets |
| 2026-11-16 13:43 | Card skimmer module added to `track.js` |
| 2026-11-16 16:38 | `eil786npto9u5bq[.]icu` and related `.icu` domains registered |
| 2026-11-16 17:13-17:57 | Second iOS host added; Coruna iframe injected for iOS 18.6 and earlier |
| 2026-11-16 ~20:40-21:10 | Mass cleanup of infected snippets begins |
| 2026-11-16 21:52 | One snippet (TalkTalk) still infected |
| 2026-11-16 23:11 | All infected Optimizely files cleaned |
| 2026-11-17 00:37 | `1688360[.]cc` placed on clientHold (NXDOMAIN) |
| 2026-11-17 03:37 | `webshell[.]lol` placed on clientHold (NXDOMAIN) |
| 2026-11-17 | Optimizely confirms remediation: vulnerable path blocked, injected code removed, sessions ended, tokens revoked, affected accounts reset |

The payload was rebuilt 26 times on November 16. Wallets were added incrementally but never removed.

## Root Cause: Optimizely Signup Flow Vulnerability

The attacker exploited a vulnerability in Optimizely's Web Experimentation signup flow that granted write access to other customers' project configurations. The specific technical details of the vulnerability have not been publicly disclosed. The attacker used this access to inject malicious JavaScript into the Project JavaScript field of customer accounts. Because the code was served from Optimizely's legitimate CDN under its own TLS certificate, it bypassed origin-based trust models and appeared as first-party code to browsers and many Content Security Policies.

## Technical Analysis of the Malicious Payload

### 1. Initial Loader (Optimizely Project JavaScript Injection)

Three loader variants were observed in the injected Project JavaScript:

1. **Plain script tag**: Creates a `<script>` element with `src` set to `hxxps://1688360[.]cc/track.js` and appends it to the document head.
2. **Base64-obfuscated**: The same URL is decoded at runtime with `atob()`, evading simple string searches for the C2 domain.
3. **Inline fallback**: The full payload is embedded in the Project JavaScript and executed with `eval` if the C2 domain is blocked — this defeats domain-based CSP restrictions.

An earlier injector used `webshell[.]lol/get.js` and was first observed on the BBC snippet at 04:21 UTC.

### 2. Crypto Clipper (Wallet Address Swapper)

The primary `track.js` payload detects valid cryptocurrency addresses across eight chains (BTC, ETH/EVM, TRON, Solana, TON, Litecoin, Bitcoin Cash, Dogecoin), validates checksums, and replaces them with attacker-controlled addresses. The clipper hooks:

- Page text nodes and form input fields
- Link `href` and image `src` attributes
- Clipboard `copy` events and `navigator.clipboard` API
- `navigator.share` (iOS share sheet)
- Outgoing `fetch` and `XMLHttpRequest` URLs and request bodies
- `window.open` and navigation events
- `Function.prototype.call` and `Function.prototype.apply` (wrapped to intercept)

The payload re-scans on DOM mutations. Replacement addresses only activate near payment-related keywords.

**Global markers set by the payload**: `window._k7`, `window.__k7b`, `window._cc`, `window._qxc`, `window._shot`

### 3. Card Skimmer

Added at 13:43 UTC on November 16. The skimmer:

- Hooks `fetch`, `XMLHttpRequest`, and form submit events
- Detects Luhn-valid card numbers with known brand prefixes, valid expiry dates, and 3-4 digit CVVs
- Exfiltrates via `navigator.sendBeacon` to `hxxps://1688360[.]cc/card.php` with fields: `n` (card number), `e` (expiry), `c` (CVV), `u` (page URL)
- Caches captured cards in `sessionStorage` under keys prefixed with `cc_`
- Cannot read cards entered in cross-origin hosted payment iframes (Stripe, Adyen, etc.)

### 4. Cookie and Screenshot Theft

Triggered once per page load, only after a successful address swap near wallet/payment wording:

- Captures a JPEG screenshot of the visible page using `html2canvas` (loaded from `hxxps://1688360[.]cc/html2canvas.min.js`)
- POSTs to `hxxps://1688360[.]cc/hit.php`: page URL, up to 8,000 characters of `document.cookie` (non-HttpOnly only), up to 20 original replaced addresses, and the screenshot
- Content-Type: `text/plain`

### 5. C2 Infrastructure

| Domain | IP | Role |
|--------|-----|------|
| `1688360[.]cc` | `136[.]113[.]106[.]136` (GCP us-central1) | Primary C2: payload hosting, card exfil, cookie/screenshot exfil |
| `eil786npto9u5bq[.]icu` | `34[.]87[.]36[.]58` (GCP Singapore) | iOS exploit router, Coruna and iOS 26 pages |
| `5vobauua3ojpklx[.]icu` | `34[.]96[.]213[.]201` (GCP Hong Kong) | iOS exploit router, `boot.js` hosting |
| `l7bcsnwc7nzr3uo[.]icu` | Behind Cloudflare | Coruna telemetry (`POST /api/iptj`) |
| `webshell[.]lol` | Unknown | Earlier injector domain (`get.js`) |
| `k68k[.]xyz` | Unknown | Exploit kit default C2, patched at runtime |

Additional cluster domains: `1y69gy2mdzaltz1[.]icu`, `gm38duxoihbmy5o[.]icu`, `p55abnw2pnsz0bo[.]icu`, `je4ft3gn8vxudum[.]icu`, `q1ls1ho9x7wsxlu[.]icu`, `ios-hack[.]icu`, `moiubpagedocs[.]cc`, `netvigator[.]cc`, `blogforge[.]vu`

SSH host key on `136[.]113[.]106[.]136`: `5e:7a:7f:b3:d7:22:ba:c7:f5:04:5a:b2:5c:0d:8a:73` (ed25519, seen Nov 5)

The C2 root page (`1688360[.]cc`) displayed a decoy page titled "闲言碎语" ("chit-chat").

### 6. Platform-Specific Behavior

#### iOS Exploit Delivery

The `boot.js` loader (served from `.icu` router domains) fingerprints the iOS version from the User-Agent and loads an exploit chain in a hidden iframe:

| iOS Version Range | Exploit Kit | Paths |
|-------------------|-------------|-------|
| iOS 13.0 to 17.x | Coruna | `/A8/`, `/JIUJIU888/index.js`, `/JIUJIU888/weifile.html` |
| iOS 18.0 to 18.7 | DarkSword | `/B9/`, `/D11/`, `/D12/` |
| iOS 26.x | Separate chain (fingerprinting only) | `/C10/` |

- Coruna telemetry: `POST /api/iptj` on `l7bcsnwc7nzr3uo[.]icu`; channel code `BIGNIAO`
- Script tag attribute: `data-channel-code="02111110"`
- Coruna loader is byte-identical to a sample from an October 2026 campaign
- Pages on iOS 18.6 or earlier reload every 60 seconds (visible symptom)
- Kit comments indicate iOS 18.7.3+ and iOS 26.3+ are patched
- No confirmed successful device compromise has been demonstrated publicly

Related file names: `rce_loader.js`, `rce_loader_v5.js`, `rce_worker_18.4.js` through `rce_worker_18.7.js`, `post_exploit.js`, `native_bridge.js`, `nb_daemon.dylib`, `evil_43818.heic`

#### Desktop Browsers (All Platforms)

The crypto clipper, card skimmer, and cookie/screenshot theft modules execute on all desktop browsers without platform-specific behavior. The payload fires on page load without requiring user interaction or consent.

### 7. Anti-Forensics / Evasion Techniques

- **Base64 obfuscation**: C2 URL encoded with `atob()` to evade string-based detection
- **Inline fallback**: Full payload embedded with `eval` as fallback when C2 domain is blocked
- **Rapid rotation**: 26 rebuilds of `track.js` in a single day; server sends `max-age=15` for fast cache expiry
- **Trusted delivery**: Payload served from `cdn.optimizely.com` with valid TLS certificate
- **CSP bypass**: `strict-dynamic` CSP allows scripts inserted by trusted scripts; `unsafe-eval` allows the inline fallback
- **Function hooking**: Wraps `Function.prototype.call` and `Function.prototype.apply` to intercept all function invocations
- **Checksum validation**: Only swaps addresses that pass chain-specific checksums, reducing visible errors

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Optimizely Web Experimentation (Project JavaScript) | 188 customer snippets modified | Malicious JS injected into customer Project JavaScript fields; served from `cdn[.]optimizely[.]com/js/<project_id>.js` |
| `cdn[.]optimizely[.]com/js/5113954737848320.js` | Rev 1796 (now clean) | Example infected snippet |
| `cdn[.]optimizely[.]com/js/6395285578973184.js` | Rev 29 (now clean) | Example infected snippet |

### File System

| File | Hash (SHA256) | Description |
|------|---------------|-------------|
| `track.js` (early build) | `acdf428f9cc564a9d16ff2a4f67e9af53dfa1bced92b4925283c8151581091fb` | Main payload (crypto clipper + card skimmer) |
| `track.js` (17:13 build) | `814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f` | Rebuilt payload variant |
| `track.js` (final build) | `f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40` | Latest payload (17:57 UTC) |
| `track.js` (28KB capture) | `617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3` | urlscan first capture |
| `index.js` | `f33e040e5416be881f103186c226ad325381a287a6d0ee1f5e9fbfddcbc24507` | iOS stage script |
| `rce_loader.js` | `e027f69d350f83965519e5ad7d947807c17d763138eaa24d2042a2f5ac6f339e` | iOS exploit loader |
| `rce_loader_v5.js` / `boot.js` | `d024dc37d8633382c3e2bed176132fd64322f4ce1c1bd11d563e700553c3b36c` | iOS exploit loader v5 |
| `D11/b.html` | `1bd3c4ed902616fefc29e92b8d8f0eaa0e8eaa96b4064f3d6c80b6e13977d3b6` | Coruna stage 1 |
| `rce_worker_18.6.js` | `54a54421cbdadc281a224713a97e3ccd9ba6dd3e2578e7e72864a47052ab4d00` | iOS 18.6 exploit worker |
| `A8 loader (a8_34ef)` | `d437b6799fc200f02832ee70a377b361471468bd887a133e26eb52832b7b2664` | Coruna A8 loader |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `1688360[.]cc` | Primary C2: payload, card exfil, cookie/screenshot exfil |
| Domain | `eil786npto9u5bq[.]icu` | iOS exploit router (Coruna, DarkSword, iOS 26) |
| Domain | `5vobauua3ojpklx[.]icu` | iOS exploit router, boot.js host |
| Domain | `l7bcsnwc7nzr3uo[.]icu` | Coruna telemetry C2 |
| Domain | `1y69gy2mdzaltz1[.]icu` | iOS stage secondary |
| Domain | `gm38duxoihbmy5o[.]icu` | iOS stage cluster |
| Domain | `p55abnw2pnsz0bo[.]icu` | iOS stage cluster |
| Domain | `je4ft3gn8vxudum[.]icu` | Fallback C2 in boot.js |
| Domain | `q1ls1ho9x7wsxlu[.]icu` | Fallback C2 |
| Domain | `ios-hack[.]icu` | Fallback C2 |
| Domain | `webshell[.]lol` | Earlier injector domain (get.js) |
| Domain | `k68k[.]xyz` | Exploit kit default C2, patched at runtime |
| Domain | `moiubpagedocs[.]cc` | Cluster host |
| Domain | `netvigator[.]cc` | Cluster host |
| Domain | `blogforge[.]vu` | Cluster host (unconfirmed) |
| IP | `136[.]113[.]106[.]136` | GCP us-central1, C2 for 1688360[.]cc |
| IP | `34[.]87[.]36[.]58` | GCP Singapore, iOS exploit hosts |
| IP | `34[.]96[.]213[.]201` | GCP Hong Kong, iOS exploit hosts |
| URL | `hxxps://1688360[.]cc/track.js` | Main payload |
| URL | `hxxps://1688360[.]cc/card.php` | Card skimmer exfiltration |
| URL | `hxxps://1688360[.]cc/hit.php` | Cookie/screenshot exfiltration |
| URL | `hxxps://1688360[.]cc/html2canvas.min.js` | Screenshot library |
| URL | `hxxps://5vobauua3ojpklx[.]icu/boot.js` | iOS exploit loader |
| URL | `hxxps://eil786npto9u5bq[.]icu/JIUJIU888/index.js` | iOS stage script |
| URL | `hxxps://eil786npto9u5bq[.]icu/JIUJIU888/weifile.html` | iOS Coruna iframe |
| URL | `hxxps://eil786npto9u5bq[.]icu/B9/rce_loader.js` | DarkSword loader |
| URL | `hxxps://eil786npto9u5bq[.]icu/C10/rce_loader_v5.js` | iOS 26 loader |
| URL | `hxxps://eil786npto9u5bq[.]icu/D11/b.html` | Coruna stage 1 |

### Cryptocurrency Wallet Addresses (Attacker-Controlled)

| Chain | Address | Role |
|-------|---------|------|
| ETH/EVM | `0xC4026b06D82b0F0B363eda0642D61CfbDc17884e` | Collector (confirmed) |
| ETH | `0x7005b45DE07e1b70DCD38eE3A708CFD88A6c7f8e` | Sweep address (confirmed) |
| ETH | `0xfb6a6A1cDc9B01dea50aab8E85Da9Ab012E9B3Cf` | Recipient (unconfirmed) |
| ETH | `0x80787af194C33b74a811f5e5c549316269d7Ee1A` | HitBTC hot wallet, cash-out (confirmed) |
| BTC | `19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW` | Accumulator (confirmed) |
| BTC | `bc1q5fljq9c4g7gsjgg4etpn6k3lyusahcvjfv0u99` | Cash-out destination (confirmed) |
| TRON | `THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa` | Collector, active since March 2026 (confirmed) |
| TRON | `TD64NDwZfQB6UASW2Xz6hWrz1T12p1pxL7` | Sweep/sink, ~462k USDT (confirmed) |
| SOL | `FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n` | Collector (no transactions) |
| TON | `UQAgM1VqSZQiJLSG5w-ovurq5CZdxLEK3_7CMmwALTA5e09p` | Collector (no transactions) |
| LTC | `ltc1q3wp7g6ds0ggg6fl6kncpa4sepn0q3qfacgred5` | Collector (confirmed) |
| LTC | `ltc1qpxvjs8u8awg8pvpwmssqlj3gzugd9vtwjtc5fc` | Cash-out destination (confirmed) |
| BCH | `qzkaaf8n6grmpr0d9lx8xutn3r9lk722f566hhpe58` | Collector (no transactions) |
| DOGE | `DBEGrxRF7KMSuhTS4c1MFviStU6efdMnu5` | Collector (no transactions) |

### Behavioral

- Global JavaScript variables set: `window._k7`, `window.__k7b`, `window._cc`, `window._qxc`, `window._shot`
- Non-native implementations of `Function.prototype.call` and `Function.prototype.apply`
- `sessionStorage` keys prefixed with `cc_` (cached captured card data)
- iOS pages reloading every 60 seconds (visible symptom of exploit kit retry)
- `data-channel-code="02111110"` attribute on injected script tags
- Telemetry string `BIGNIAO` in Coruna communications
- Decoy page title "闲言碎语" on C2 root

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Exploited Optimizely platform vulnerability to inject malicious JS into 188 customer project snippets served from legitimate CDN |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Malicious JavaScript payload executed in victim browsers via injected Optimizely snippets |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication and exfiltration via HTTP/HTTPS to `1688360[.]cc` endpoints |
| T1185 | Browser Session Hijacking | Hooking of `fetch`, XHR, clipboard, `navigator.share`, and form submit events to intercept and modify browser sessions |
| T1005 | Data from Local System | Stealing cookies via `document.cookie`, capturing screenshots via html2canvas |
| T1041 | Exfiltration Over C2 Channel | Card data exfiltrated to `/card.php`, cookies/screenshots to `/hit.php` via same C2 infrastructure |
| T1056.004 | Input Capture: Credential API Hooking | Card skimmer hooks form submissions and network requests to capture payment card data |
| T1565.002 | Data Manipulation: Transmitted Data Manipulation | Crypto clipper replaces wallet addresses in page content, clipboard, outgoing requests, and navigation URLs |
| T1189 | Drive-by Compromise | iOS visitors silently routed to Coruna and DarkSword exploit kits via hidden iframes |
| T1027 | Obfuscated Files or Information | Base64-encoded C2 URLs, rapid payload rotation (26 builds), inline eval fallback |

## Impact Assessment

- **Breadth**: 188 Optimizely snippets across 178 organizations, spanning banking/finance (32), technology/SaaS (23), retail/fashion (20), streaming/entertainment (12), and news/media (10) sectors. Named victims include BBC, CNN, Zoom, HSBC, Equifax, Ledger, IKEA, GitLab, Mutual of Omaha, TalkTalk, Vodafone, and Scheels.
- **Depth**: The payload had full access to the page DOM, non-HttpOnly cookies, and all user interactions on affected pages. Card data entered on affected checkout pages was at risk (except where hosted payment iframes were used). iOS visitors on versions prior to 18.7.3 were exposed to exploit kit delivery.
- **Financial impact**: Approximately $7,150 confirmed stolen via cryptocurrency address swapping (BTC: $5,489; LTC: $760; TRON: $719; ETH: $101; BSC: $82). Card theft and cookie theft volumes are unknown.
- **CSP analysis**: Of 256 affected hosts evaluated, 68 had no CSP, 50 had a CSP that allowed both payload execution and data theft, 17 blocked data theft but not payload execution, and only 24 (15%) fully blocked the payload.

## Detection & Remediation

### Immediate Detection

Search web proxy, DNS, and firewall logs from 2026-11-16 04:00 UTC onward for the following domains:
- `1688360[.]cc`
- `webshell[.]lol`
- `eil786npto9u5bq[.]icu`
- `5vobauua3ojpklx[.]icu`
- `l7bcsnwc7nzr3uo[.]icu`
- Any `.icu` domain resolving to `34[.]87[.]36[.]58` or `34[.]96[.]213[.]201`

Check CSP violation reports for blocked requests to any of the above domains.

Review Optimizely Project JavaScript fields for the strings: `1688360`, `atob(`, `webshell`, `track.js`, `eval(`.

Search browser `sessionStorage` for keys prefixed with `cc_` on any page that loads Optimizely.

### Remediation

1. **Immediate**: Review and clean all Optimizely Project JavaScript fields; audit experiment custom code for unauthorized modifications.
2. **Credential rotation**: Review and rotate all Optimizely users, API tokens, and integrations. Remove any unrecognized entries.
3. **Card data**: Treat all payment card data entered on affected pages between 04:00 and 23:11 UTC on November 16 as compromised. Notify payment processors and affected cardholders.
4. **Session tokens**: Rotate non-HttpOnly session cookies/tokens for affected sites.
5. **iOS users**: Advise visitors to update to iOS 18.7.3+ or iOS 26.3+.
6. **Network blocking**: Block the domains and IPs listed in the IOC section at the firewall/proxy level.

### Long-Term Hardening

1. **Content Security Policy**: Deploy restrictive CSPs with explicit `script-src` and `connect-src` allowlists. Avoid `'strict-dynamic'` and `'unsafe-eval'` on sensitive pages (authentication, checkout).
2. **Payment isolation**: Isolate payment collection in cross-origin hosted iframes (Stripe, Adyen, etc.). Strip non-essential third-party tags from checkout and authentication pages.
3. **Third-party monitoring**: Deploy CSP reporting and script monitoring (e.g., Report URI Script Watch) to detect unauthorized script dependencies.
4. **Supply chain review**: Audit all third-party JavaScript dependencies. Consider self-hosting critical scripts with pinned integrity hashes where possible.
5. **Network segmentation**: Ensure checkout and authentication pages load minimal third-party code.

## Detection Rules

The following detection rules cover OPTIMJACK C2 domain access, exfiltration paths, iOS exploit kit indicators, and malicious payload artifacts. All rules target confirmed IOCs at specific altitude. Domains are the most durable indicators since file hashes rotated across 26 builds. Snort rules are structurally validated only (Snort not installed in this environment).

### Sigma: OPTIMJACK C2 Domain Access via Proxy

Detects web proxy requests to any of the 14 known OPTIMJACK C2 and infrastructure domains.

<!-- audit: compile ✅ sigma convert splunk+log_scale passed; 14 domains from confirmed IOC sources (Report URI, StepSecurity, Unit42); proxy logsource category uses c-uri field; no defanged values in rule; FP rate near-zero given domain specificity -->

**Compile**: ✅ sigma convert (splunk, log_scale) | **Confidence**: high

```yaml
title: OPTIMJACK Supply Chain Attack - C2 Domain Access via Proxy
id: 7a3e1c4f-9b2d-4e8a-b6c5-1d0f3e7a9b2c
status: experimental
description: >
    Detects web proxy requests to known OPTIMJACK C2 and exfiltration domains
    used in the Optimizely supply chain attack on November 16, 2026. The
    attacker injected malicious JavaScript into Optimizely customer projects
    that loaded payloads from these domains.
references:
    - https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
    - https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
    - https://www.stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer
author: Actioner
date: 2026-11-18
tags:
    - attack.t1195.002
    - attack.t1059.007
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains:
            - '1688360.cc'
            - 'eil786npto9u5bq.icu'
            - '5vobauua3ojpklx.icu'
            - 'l7bcsnwc7nzr3uo.icu'
            - '1y69gy2mdzaltz1.icu'
            - 'gm38duxoihbmy5o.icu'
            - 'p55abnw2pnsz0bo.icu'
            - 'je4ft3gn8vxudum.icu'
            - 'q1ls1ho9x7wsxlu.icu'
            - 'ios-hack.icu'
            - 'webshell.lol'
            - 'moiubpagedocs.cc'
            - 'netvigator.cc'
            - 'k68k.xyz'
    condition: selection
falsepositives:
    - Unlikely given the specificity of these domains
level: critical
```

### Sigma: OPTIMJACK DNS Query to C2 Domains

Detects DNS resolution attempts for known OPTIMJACK domains from endpoint DNS query logs (Sysmon EID 22 or equivalent).

<!-- audit: compile ✅ sigma convert splunk+log_scale passed; uses dns_query logsource with QueryName|endswith for proper subdomain matching; domains are not defanged; same 14 confirmed domains -->

**Compile**: ✅ sigma convert (splunk, log_scale) | **Confidence**: high

```yaml
title: OPTIMJACK Supply Chain Attack - DNS Query to C2 Domains
id: 8b4f2d5e-0c3a-4f9b-a7d6-2e1a4b8c0d3e
status: experimental
description: >
    Detects DNS resolution attempts for known OPTIMJACK command and control
    domains associated with the Optimizely supply chain attack. These domains
    hosted the malicious track.js payload, card skimmer exfiltration endpoints,
    and iOS exploit kit infrastructure.
references:
    - https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
    - https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/
author: Actioner
date: 2026-11-18
tags:
    - attack.t1195.002
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '1688360.cc'
            - 'eil786npto9u5bq.icu'
            - '5vobauua3ojpklx.icu'
            - 'l7bcsnwc7nzr3uo.icu'
            - '1y69gy2mdzaltz1.icu'
            - 'gm38duxoihbmy5o.icu'
            - 'p55abnw2pnsz0bo.icu'
            - 'je4ft3gn8vxudum.icu'
            - 'q1ls1ho9x7wsxlu.icu'
            - 'ios-hack.icu'
            - 'webshell.lol'
            - 'moiubpagedocs.cc'
            - 'netvigator.cc'
            - 'k68k.xyz'
    condition: selection
falsepositives:
    - Unlikely given the specificity of these domains
level: critical
```

### Sigma: OPTIMJACK Exfiltration Path Access

Detects proxy requests combining the primary C2 domain with specific exfiltration and payload paths.

<!-- audit: compile ✅ sigma convert splunk+log_scale passed; AND condition requires both domain and path match; reduces false positives below domain-only matching; card.php/hit.php/track.js are confirmed exfil/payload endpoints -->

**Compile**: ✅ sigma convert (splunk, log_scale) | **Confidence**: high

```yaml
title: OPTIMJACK Supply Chain Attack - Exfiltration Path Access
id: 9c5a3e6f-1d4b-5a0c-b8e7-3f2a5b9c1d4e
status: experimental
description: >
    Detects HTTP requests to specific URL paths used by the OPTIMJACK payload
    for card data exfiltration (card.php), cookie and screenshot theft (hit.php),
    and payload delivery (track.js) on the primary C2 domain 1688360.cc.
references:
    - https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
    - https://www.stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer
author: Actioner
date: 2026-11-18
tags:
    - attack.t1041
    - attack.t1005
logsource:
    category: proxy
detection:
    selection_domain:
        c-uri|contains: '1688360.cc'
    selection_paths:
        c-uri|contains:
            - '/track.js'
            - '/card.php'
            - '/hit.php'
            - '/html2canvas.min.js'
    condition: selection_domain and selection_paths
falsepositives:
    - None expected for this specific domain and path combination
level: critical
```

### Suricata: OPTIMJACK Network Detection (12 rules)

Twelve Suricata rules covering HTTP payload download, card/cookie exfiltration, DNS lookups for C2 domains, iOS exploit kit path access, Coruna telemetry, and TLS SNI matching.

<!-- audit: compile ✅ suricata -T passed; all rules use dot-notation sticky buffers; http protocol for HTTP rules, dns for DNS, tls for SNI; flow directives present on all TCP-based rules; unique SIDs in 2100101-2100112 range; no defanged values -->

**Compile**: ✅ suricata -T | **Confidence**: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK track.js Payload Download from C2"; flow:established,to_server; http.host; content:"1688360.cc"; fast_pattern; http.uri; content:"/track.js"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:2100101; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK Card Skimmer Exfiltration to card.php"; flow:established,to_server; http.host; content:"1688360.cc"; fast_pattern; http.uri; content:"/card.php"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:2100102; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK Cookie and Screenshot Exfiltration to hit.php"; flow:established,to_server; http.host; content:"1688360.cc"; fast_pattern; http.uri; content:"/hit.php"; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:2100103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK Primary C2 Domain DNS Lookup (1688360.cc)"; dns.query; content:"1688360.cc"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:2100104; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK iOS Exploit Kit Domain DNS Lookup (eil786npto9u5bq.icu)"; dns.query; content:"eil786npto9u5bq.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:2100105; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK iOS Exploit Kit Domain DNS Lookup (5vobauua3ojpklx.icu)"; dns.query; content:"5vobauua3ojpklx.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:2100106; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK Telemetry Domain DNS Lookup (l7bcsnwc7nzr3uo.icu)"; dns.query; content:"l7bcsnwc7nzr3uo.icu"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:2100107; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - OPTIMJACK Injector Domain DNS Lookup (webshell.lol)"; dns.query; content:"webshell.lol"; nocase; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:2100108; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK iOS boot.js Exploit Loader Download"; flow:established,to_server; http.uri; content:"/boot.js"; http.host; content:".icu"; endswith; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:2100109; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK Coruna Exploit Kit JIUJIU888 Path Access"; flow:established,to_server; http.uri; content:"/JIUJIU888/"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:2100110; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK Coruna Telemetry POST to /api/iptj"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/iptj"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:2100111; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - OPTIMJACK TLS Connection to C2 Domain 1688360.cc"; flow:established,to_server; tls.sni; content:"1688360.cc"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:2100112; rev:1;)
```

### YARA: OPTIMJACK Payload Detection (3 rules)

Three YARA rules detecting the malicious track.js payload (via behavioral markers and C2/exfil strings), the iOS boot.js exploit loader (via path markers and domain fragments), and known file hashes.

<!-- audit: compile ✅ yarac passed (all 3 rules); SupplyChain_OPTIMJACK_TrackJS_Payload matches on window._k7/_cc/_qxc/_shot globals + exfil paths + wallet addresses; SupplyChain_OPTIMJACK_BootJS_iOS_Loader matches on JIUJIU888/BIGNIAO/02111110 + .icu domain fragments; SupplyChain_OPTIMJACK_Known_Hashes covers 10 SHA256 hashes from File System IOC table (4 track.js builds + iOS loaders + Coruna stages); hash rule uses import "hash" module; filesize limits prevent scanning overhead; no PE-only conditions since targets are JavaScript -->

**Compile**: ✅ yarac | **Confidence**: high (behavioral rules), medium (hash rule — hashes rotated across builds)

```yara
import "hash"

rule SupplyChain_OPTIMJACK_TrackJS_Payload
{
    meta:
        description = "Detects OPTIMJACK malicious track.js payload used in Optimizely supply chain attack. Matches crypto clipper, card skimmer, and screenshot theft markers."
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $marker1 = "window._k7" ascii
        $marker2 = "window._cc" ascii
        $marker3 = "window._qxc" ascii
        $marker4 = "window._shot" ascii
        $marker5 = "window.__k7b" ascii

        $exfil1 = "/card.php" ascii
        $exfil2 = "/hit.php" ascii
        $exfil3 = "html2canvas" ascii

        $c2_1 = "1688360.cc" ascii
        $c2_2 = "1688360" ascii

        $wallet_eth = "0xC4026b06D82b0F0B363eda0642D61CfbDc17884e" ascii nocase
        $wallet_btc = "19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW" ascii
        $wallet_trx = "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa" ascii

        $func1 = "navigator.sendBeacon" ascii
        $func2 = "Function.prototype.call" ascii
        $func3 = "Function.prototype.apply" ascii
        $func4 = "navigator.clipboard" ascii

    condition:
        filesize < 1MB and
        (
            (3 of ($marker*)) or
            (1 of ($c2*) and 1 of ($exfil*)) or
            (2 of ($wallet*) and 1 of ($func*)) or
            (2 of ($marker*) and 1 of ($exfil*))
        )
}

rule SupplyChain_OPTIMJACK_BootJS_iOS_Loader
{
    meta:
        description = "Detects OPTIMJACK boot.js iOS exploit kit loader that fingerprints iOS version and loads Coruna or DarkSword exploit chains in hidden iframes."
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $channel = "02111110" ascii
        $marker = "BIGNIAO" ascii
        $path1 = "JIUJIU888" ascii
        $path2 = "/boot.js" ascii
        $path3 = "rce_loader" ascii
        $path4 = "rce_worker" ascii
        $path5 = "weifile.html" ascii
        $path6 = "data-channel-code" ascii

        $domain1 = "eil786npto9u5bq" ascii
        $domain2 = "5vobauua3ojpklx" ascii
        $domain3 = "l7bcsnwc7nzr3uo" ascii

        $ios_check = "iPhone" ascii
        $ios_check2 = "iPad" ascii

    condition:
        filesize < 500KB and
        (
            (2 of ($path*) and 1 of ($domain*)) or
            ($marker and 1 of ($path*)) or
            ($channel and 1 of ($domain*)) or
            (1 of ($domain*) and $path1 and ($ios_check or $ios_check2))
        )
}

rule SupplyChain_OPTIMJACK_Known_Hashes
{
    meta:
        description = "Detects known OPTIMJACK malicious files by SHA256 hash. Covers track.js payload builds, iOS exploit loaders, and Coruna stage files. Forensic lookback rule — hashes rotated across 26 builds on Nov 16."
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/"
        tlp = "WHITE"
        severity = "critical"
        hash1 = "acdf428f9cc564a9d16ff2a4f67e9af53dfa1bced92b4925283c8151581091fb"
        hash2 = "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f"
        hash3 = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"
        hash4 = "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3"
        hash5 = "f33e040e5416be881f103186c226ad325381a287a6d0ee1f5e9fbfddcbc24507"
        hash6 = "e027f69d350f83965519e5ad7d947807c17d763138eaa24d2042a2f5ac6f339e"
        hash7 = "d024dc37d8633382c3e2bed176132fd64322f4ce1c1bd11d563e700553c3b36c"
        hash8 = "1bd3c4ed902616fefc29e92b8d8f0eaa0e8eaa96b4064f3d6c80b6e13977d3b6"
        hash9 = "54a54421cbdadc281a224713a97e3ccd9ba6dd3e2578e7e72864a47052ab4d00"
        hash10 = "d437b6799fc200f02832ee70a377b361471468bd887a133e26eb52832b7b2664"

    condition:
        hash.sha256(0, filesize) == "acdf428f9cc564a9d16ff2a4f67e9af53dfa1bced92b4925283c8151581091fb" or
        hash.sha256(0, filesize) == "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f" or
        hash.sha256(0, filesize) == "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40" or
        hash.sha256(0, filesize) == "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3" or
        hash.sha256(0, filesize) == "f33e040e5416be881f103186c226ad325381a287a6d0ee1f5e9fbfddcbc24507" or
        hash.sha256(0, filesize) == "e027f69d350f83965519e5ad7d947807c17d763138eaa24d2042a2f5ac6f339e" or
        hash.sha256(0, filesize) == "d024dc37d8633382c3e2bed176132fd64322f4ce1c1bd11d563e700553c3b36c" or
        hash.sha256(0, filesize) == "1bd3c4ed902616fefc29e92b8d8f0eaa0e8eaa96b4064f3d6c80b6e13977d3b6" or
        hash.sha256(0, filesize) == "54a54421cbdadc281a224713a97e3ccd9ba6dd3e2578e7e72864a47052ab4d00" or
        hash.sha256(0, filesize) == "d437b6799fc200f02832ee70a377b361471468bd887a133e26eb52832b7b2664"
}
```

### Snort: OPTIMJACK Network Detection (6 rules)

Six Snort 3 rules covering payload download, card/cookie exfiltration, and exploit kit path access.

<!-- audit: ⚠️ uncompiled — Snort not installed; structural validation only: underscore-notation sticky buffers (http_method, http_uri, http_host), flow directives, unique SIDs 1100001-1100006, balanced parentheses, semicolon termination verified. Rev 1.1: fixed SIDs 1100001/1100002/1100003/1100005 — replaced http_header with http_host for domain-matching content (http_header matches all raw headers, http_host matches the Host header specifically). -->

**Compile**: ⚠️ uncompiled (structural check only) | **Confidence**: medium

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - OPTIMJACK track.js Payload Download"; flow:established,to_server; content:"GET"; http_method; content:"/track.js"; http_uri; content:"1688360.cc"; http_host; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:1100001; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - OPTIMJACK Card Skimmer Exfil to card.php"; flow:established,to_server; content:"POST"; http_method; content:"/card.php"; http_uri; content:"1688360.cc"; http_host; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:1100002; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - OPTIMJACK Cookie Screenshot Exfil to hit.php"; flow:established,to_server; content:"POST"; http_method; content:"/hit.php"; http_uri; content:"1688360.cc"; http_host; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:1100003; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - OPTIMJACK Coruna Exploit JIUJIU888 Path"; flow:established,to_server; content:"/JIUJIU888/"; http_uri; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:1100004; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - OPTIMJACK iOS boot.js Loader on ICU Domain"; flow:established,to_server; content:"/boot.js"; http_uri; content:".icu"; http_host; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:1100005; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - OPTIMJACK Coruna Telemetry POST /api/iptj"; flow:established,to_server; content:"POST"; http_method; content:"/api/iptj"; http_uri; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/optimjack-supply-chain-attack/; metadata:author Actioner, created_at 2026-11-18; sid:1100006; rev:1;)
```

## Lessons Learned

1. **Third-party JavaScript is a single point of failure.** The OPTIMJACK attack demonstrates that even trusted, widely-deployed experimentation platforms can become a vehicle for mass compromise. A single vulnerability in Optimizely's signup flow gave the attacker write access to 188 customer projects, turning a legitimate CDN into a malware delivery network. Organizations must treat all third-party JavaScript as a potential attack vector, not just untrusted sources.

2. **Content Security Policy is necessary but not sufficient.** Only 15% of affected organizations had CSPs that blocked the payload entirely. The widespread use of `'strict-dynamic'` (which trusts any script inserted by a trusted script) and `'unsafe-eval'` (which allowed the inline fallback to execute) undermined CSP protections. Payment and authentication pages need restrictive, hand-tuned CSPs — not broad policies that inherit trust from third-party scripts.

3. **Multi-payload supply chain attacks maximize monetization.** Rather than deploying a single payload, the attacker ran a crypto clipper, card skimmer, cookie stealer, screenshot tool, and iOS exploit kits simultaneously — all through the same injection point. This "portfolio" approach means that even organizations without cryptocurrency exposure or e-commerce checkout pages were still at risk from cookie theft and iOS exploitation.

4. **Rapid iteration defeats hash-based detection.** The payload was rebuilt 26 times in a single day with `max-age=15` caching. File hash IOCs are useful only for forensic lookback, not real-time blocking. Domain-based and behavioral detection (global variable markers, function hooking patterns, exfiltration endpoints) are the durable indicators for this class of attack.

## Sources

- [Unit42 - Borrowed Code, Real Consequences: What OPTIMJACK Teaches Us](https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/) — primary technical analysis and attack naming
- [Report URI - World's Largest Brands Infected with Malware via Optimizely](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/) — original discovery, CSP analysis, timeline, and comprehensive IOCs
- [StepSecurity - OPTIMJACK: Optimizely-Hosted Scripts Loaded a Crypto Clipper and Card Skimmer on 178 Organizations](https://www.stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer) — detailed technical analysis with wallet addresses, loader variants, and payload behavior
- [Krebs on Security - Attackers Used Optimizely to A/B Test Malware on Top Websites](https://krebsonsecurity.com/2026/11/attackers-used-optimizely-to-a-b-test-malware-on-top-websites/) — mainstream coverage, affected organizations, CSP statistics
- [The Record - Malicious Code Served Through Optimizely Hit Nearly 190 Sites](https://therecord.media/optimizely-malicious-code-customer-sites) — additional timeline details, Black Duck and InfoStealers research references
- [GitHub - jejex0/optimjack-chain](https://github.com/jejex0/optimjack-chain) — community-maintained IOC repository with domains, IPs, wallet addresses, and file hashes (verify before production use)

---
*Report generated by Actioner*
