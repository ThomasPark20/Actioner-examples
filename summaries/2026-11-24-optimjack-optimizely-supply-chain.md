# OPTIMJACK: Optimizely Web Experimentation Supply Chain Attack

**Date:** 2026-11-24  
**Status:** DRAFT  
**TLP:** CLEAR  
**Author:** Actioner  

---

## Executive Summary

On November 16, 2026, a threat actor exploited a vulnerability in Optimizely's Web Experimentation account signup flow to inject malicious JavaScript into the platform's customer-editable "Project JavaScript" field. The tampered code was served from Optimizely's legitimate CDN under its own TLS certificate to visitors of at least 178 organizations, including BBC, CNN, Zoom, Salesforce, GitLab, IKEA, HSBC, Equifax, and Ledger. The campaign, dubbed **OPTIMJACK**, deployed a multi-purpose browser payload that performed cryptocurrency wallet address swapping, payment card skimming, cookie theft, page screenshots, and iOS exploit kit delivery targeting Coruna (iOS 13-17) and DarkSword (iOS 18.x) chains. The payload was rebuilt 26 times during the attack window (04:21-23:11 UTC on November 16). Optimizely patched the vulnerability and removed injected code by 01:02 UTC on November 17. Financial losses included approximately $7,500 in cryptocurrency and an unknown number of stolen payment card records.

---

## Background

Optimizely Web Experimentation is a widely-deployed A/B testing and experience optimization platform. Customer websites include a JavaScript "snippet" loaded from `cdn.optimizely.com` (or customer-hosted equivalents) that executes on every page load, typically without being gated behind user consent. The platform provides a "Project JavaScript" field where customers can add custom code that runs alongside experiments. The attacker exploited a vulnerability in Optimizely's Experimentation account signup flow to gain write access to this field across multiple customer projects, turning a trusted third-party script into a supply chain weapon.

### Timeline (UTC)

| Time | Event |
|------|-------|
| 2026-11-09 | iOS exploit `.icu` domains registered (5vobauua3ojpklx, p55abnw2pnsz0bo, je4ft3gn8vxudum) |
| 2026-11-13 | Related compromises reported: Kissmetrics (securitybank[.]com), StorifyMe (faz[.]net), minute-ly (foxsports[.]com) |
| 2026-11-16 05:23 | Primary C2 domain `1688360[.]cc` registered |
| 2026-11-16 04:21 | First Optimizely injection observed (BBC snippet) |
| 2026-11-16 13:43 | Card skimmer component activated |
| 2026-11-16 16:38 | Additional `.icu` domains registered (eil786npto9u5bq, 1y69gy2mdzaltz1, gm38duxoihbmy5o) |
| 2026-11-16 17:13 | track.js build SHA256 `814a963c...` captured |
| 2026-11-16 17:56 | Final track.js build SHA256 `f7b84b9a...` goes live |
| 2026-11-16 21:52 | 1 of 188 known infected snippets still active |
| 2026-11-17 00:37 | `1688360[.]cc` placed on clientHold (NXDOMAIN) |
| 2026-11-17 01:02 | Optimizely patches vulnerability, removes injected code, secures accounts |
| 2026-11-17 03:37 | `webshell[.]lol` placed on clientHold |

---

## Technical Analysis

### Stage 1: Initial Access - Optimizely Account Compromise (T1195.002)

The attacker exploited a vulnerability in Optimizely's Experimentation account signup flow to gain unauthorized write access to the "Project JavaScript" field across customer projects. The injected loader took three forms:

1. **Plain script tag** pointing to `https://1688360[.]cc/track.js`
2. **Base64-obfuscated variant** using `atob()` to decode the C2 URL at runtime
3. **Inline eval fallback** containing a full copy of the financial payload, executed via `eval()` if the remote domain is blocked or takes longer than ~2.5 seconds to respond

Since Optimizely snippets fire on page load without consent gating, no user interaction was needed to trigger execution.

### Stage 2: Payload Delivery (T1059.007)

The injected loader fetched `track.js` from `1688360[.]cc`. The payload was served with `cache-control: max-age=15` and was rebuilt 26 times during the attack window. The script loaded from the legitimate Optimizely CDN, inheriting the same-origin trust of the host website.

### Stage 3: Cryptocurrency Clipper (T1565.002, T1115)

The payload monitored and replaced cryptocurrency wallet addresses across multiple surfaces:

- DOM text content and form inputs
- Link and image attributes
- Copy events and Clipboard API
- `navigator.share` calls
- `fetch` and `XHR` request URL and body content
- `Function.prototype.call` and `Function.prototype.apply` hooks

Address replacement was performed only for checksum-valid addresses when nearby text contained payment terms ("wallet", "deposit", "send"). Targeted chains: BTC, ETH/EVM, TRON, Solana, TON, LTC, BCH, and DOGE.

### Stage 4: Payment Card Skimmer (T1056)

Beginning at 13:43 UTC, the payload:

- Wrapped `fetch` and `XMLHttpRequest` to intercept outgoing requests
- Listened for form submission events
- Applied Luhn validation, brand-prefix matching, expiry validation, and 3-4 digit CVV checks
- Exfiltrated card data via `navigator.sendBeacon` to `https://1688360[.]cc/card.php` with fields `n` (number), `e` (expiry), `c` (CVV), `u` (page URL)
- Stored captured cards in `sessionStorage` with keys prefixed `cc_` to avoid re-capture

### Stage 5: Session Data Collection (T1113, T1185)

The payload collected:

- Page URL
- Up to 8,000 characters of `document.cookie` (non-HttpOnly)
- Up to 20 original cryptocurrency addresses that were swapped
- A JPEG screenshot of the page via `html2canvas` (loaded from `1688360[.]cc/html2canvas.min.js`)

Data was exfiltrated via POST with `text/plain` body to `https://1688360[.]cc/hit.php`.

### Stage 6: iOS Exploit Kit Delivery (T1189, T1203)

For visitors on iPhone, iPad, or iPod (detected via user-agent), the payload performed version-based routing to exploit chains:

| iOS Version | Path | Exploit Kit |
|-------------|------|-------------|
| 13-17 | `/A8/a.html` | Coruna |
| 15-17 (selected) | `/D11/b.html` | DarkSword |
| 18.x | `/B9/b.html`, `/D12/b.html` | DarkSword |
| 26 | `/C10/c.html` | Unknown (fingerprinting only) |

Exploit delivery used hidden zero-width iframes. For iOS 18.6 and earlier, pages reloaded every 60 seconds to retry exploitation. The iOS loader (`boot.js`) was served from `.icu` domains with `data-channel-code="02111110"` and `data-chain-url` attributes. Post-exploitation included upload of `keychain-2.db`.

The iOS exploit modules used a naming scheme based on `sha256("cecd08aa6ff548c2" + module_id)`, first 40 hex characters, plus `.js`.

### CSP Effectiveness

Per Report URI's analysis of affected sites:

- 68 sites (38%) had **no CSP** at all
- 50 sites (28%) had a CSP that **still allowed** both the payload and exfiltration
- 24 sites (15%) had a CSP that **fully blocked** the payload
- Overall CSP deployment across the busiest sites is approximately 10%

---

## Indicators of Compromise

> All indicators below are defanged for safe handling. Remove `[.]` brackets for operational use.

### Domains

| Domain | Role | Registration/Status |
|--------|------|---------------------|
| `1688360[.]cc` | Primary C2 / payload / exfil | Registered 2026-11-16 05:23 UTC; clientHold 2026-11-17 00:37 UTC |
| `webshell[.]lol` | Earlier-wave injector (/get.js) | clientHold 2026-11-17 03:37 UTC |
| `linkforge[.]cc` | SEO backlink panel (earlier wave) | -- |
| `5vobauua3ojpklx[.]icu` | iOS exploit router | Registered 2026-11-09 |
| `eil786npto9u5bq[.]icu` | iOS exploit router | Registered 2026-11-16 16:38 UTC |
| `l7bcsnwc7nzr3uo[.]icu` | Coruna telemetry (/api/iptj) | Registered 2026-10-28 |
| `je4ft3gn8vxudum[.]icu` | Fallback C2 (boot.js) | Registered 2026-11-09 |
| `ios-hack[.]icu` | Fallback C2 (boot.js) | Registered 2026-11-16 23:39 UTC |
| `p55abnw2pnsz0bo[.]icu` | iOS stage | Registered 2026-11-09 |
| `1y69gy2mdzaltz1[.]icu` | iOS stage | Registered 2026-11-16 16:38 UTC |
| `gm38duxoihbmy5o[.]icu` | iOS stage | Registered 2026-11-16 16:38 UTC |
| `q1ls1ho9x7wsxlu[.]icu` | iOS stage (secondary C2) | Registered 2026-11-16 23:44 UTC |

### IP Addresses

| IP | Role | Cloud Provider |
|----|------|---------------|
| `136[.]113[.]106[.]136` | Last A record for 1688360[.]cc | Google Cloud (us-central1) |
| `34[.]87[.]36[.]58` | Hosted Nov 16 .icu batch | Google Cloud (Singapore) |
| `34[.]96[.]213[.]201` | Hosted Nov 9 .icu batch | Google Cloud (Hong Kong) |

### URLs / Endpoints

| URL | Purpose |
|-----|---------|
| `hxxps://1688360[.]cc/track.js` | Main payload delivery |
| `hxxps://1688360[.]cc/card.php` | Card data exfiltration (POST, sendBeacon) |
| `hxxps://1688360[.]cc/hit.php` | Session/screenshot exfiltration (POST) |
| `hxxps://1688360[.]cc/html2canvas.min.js` | Screenshot library |
| `hxxps://webshell[.]lol/get.js` | Earlier-wave injector |
| `hxxps://<icu-domain>/boot.js` | iOS exploit loader |
| `hxxps://<icu-domain>/JIUJIU888/weifile.html` | iOS exploit iframe (iOS <= 18.6) |
| `hxxps://<icu-domain>/JIUJIU888/index.js` | iOS exploit code |
| `hxxps://<icu-domain>/A8/a.html` | Coruna iOS 13-17 |
| `hxxps://<icu-domain>/B9/b.html` | DarkSword iOS 18.x |
| `hxxps://<icu-domain>/D11/b.html` | DarkSword iOS 15-17 |
| `hxxps://<icu-domain>/C10/c.html` | iOS 26 fingerprint |
| `hxxps://l7bcsnwc7nzr3uo[.]icu/api/iptj` | Coruna telemetry (POST) |

### File Hashes (SHA-256)

| Hash | Description |
|------|-------------|
| `617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3` | track.js (first capture, ~28 KB) |
| `814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f` | track.js (17:13 UTC build) |
| `f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40` | track.js (final build, 17:56 UTC) |
| `c2a34c579e4c2e8802752c93b3a9cca0230610f3e4dd6688f4272459c7c7c162` | Decoded inline financial fallback (24,392 bytes) |

### Attacker Wallet Addresses

| Network | Address |
|---------|---------|
| Ethereum | `0xC4026b06D82b0F0B363eda0642D61CfbDc17884e` |
| Bitcoin | `19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW` |
| Litecoin | `ltc1q3wp7g6ds0ggg6fl6kncpa4sepn0q3qfacgred5` |
| TRON | `THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa` |
| TON | `UQAgM1VqSZQiJLSG5w-ovurq5CZdxLEK3_7CMmwALTA5e09p` |
| Solana | `FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n` |
| Bitcoin Cash | `qzkaaf8n6grmpr0d9lx8xutn3r9lk722f566hhpe58` |
| Dogecoin | `DBEGrxRF7KMSuhTS4c1MFviStU6efdMnu5` |

### JavaScript Artifacts

| Indicator | Type |
|-----------|------|
| `window._k7` | Global variable (payload state) |
| `window.__k7b` | Global variable (payload state) |
| `window._cc` | Global variable (card skimmer) |
| `window._qxc` | Global variable |
| `window._shot` | Global variable (screenshot) |
| `data-channel-code="02111110"` | iOS loader attribute |
| `sessionStorage` keys prefixed `cc_` | Captured card storage |
| Non-native `Function.prototype.call` / `.apply` | Monkey-patched by payload |

### SSH Host Key

| Fingerprint | Host |
|-------------|------|
| ed25519 `5e:7a:7f:b3:d7:22:ba:c7:f5:04:5a:b2:5c:0d:8a:73` | `136[.]113[.]106[.]136` (Shodan, 2026-11-05) |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Compromise Software Supply Chain | T1195.002 | Exploitation of Optimizely signup flow to inject malicious Project JavaScript |
| JavaScript | T1059.007 | Malicious JavaScript payload execution in victim browsers |
| Drive-by Compromise | T1189 | iOS exploit kit delivery via hidden iframes |
| Exploitation for Client Execution | T1203 | Coruna and DarkSword exploit chains targeting iOS vulnerabilities |
| Input Capture | T1056 | Payment card skimming via form interception |
| Clipboard Data | T1115 | Cryptocurrency wallet address replacement via clipboard hooks |
| Screen Capture | T1113 | Page screenshots via html2canvas |
| Browser Session Hijacking | T1185 | Cookie theft and session data collection |
| Transmitted Data Manipulation | T1565.002 | Cryptocurrency address replacement in outgoing transactions |
| Acquire Infrastructure: Server | T1583.004 | Google Cloud infrastructure for C2 and exploit delivery |

---

## Detection & Remediation

### Immediate Actions

1. **Block IOC domains and IPs** at DNS, proxy, and firewall layers
2. **Audit Optimizely Project JavaScript** for all customer projects, diff against known-good copies for changes made between 2026-11-16 04:00 UTC and 2026-11-17 02:00 UTC
3. **Review Optimizely change logs** for the attack window
4. **Treat payment data as compromised** for checkout pages active during the attack window
5. **Notify affected iOS users** (versions 18.7.2 and earlier) to update to iOS 18.7.3+ or 26.3+
6. **Monitor attacker wallets** for transaction activity

### Hardening Recommendations

1. **Deploy strict Content Security Policy** with explicit `script-src` directives that do not use `unsafe-eval` or `unsafe-inline`
2. **Isolate payment collection** in hardened cross-origin iframes
3. **Remove third-party marketing/analytics scripts** from authentication and checkout pages
4. **Implement Subresource Integrity (SRI)** for third-party scripts where supported
5. **Monitor CSP violation reports** for unauthorized script sources
6. **Establish change detection** for third-party script content (hash-based monitoring)
7. **Restrict third-party script capabilities** via Feature Policy / Permissions Policy

---

## Detection Rules

### Sigma Rules

**Rule 1: DNS Query to Known C2 Domains**  
File: `sigma_optimjack_dns.yml`  
Compile status: Passes `sigma convert` to Splunk and LogScale  
Confidence: HIGH (IOC-specific, all domains confirmed by multiple sources)

Detects DNS resolution of any OPTIMJACK-associated domain. Covers the primary C2 (`1688360[.]cc`), earlier-wave infrastructure (`webshell[.]lol`, `linkforge[.]cc`), and all iOS exploit `.icu` domains.

**Rule 2: Web Proxy Request to Exfiltration Endpoints**  
File: `sigma_optimjack_proxy.yml`  
Compile status: Passes `sigma convert` to Splunk and LogScale  
Confidence: HIGH (requires both domain AND specific path match)

Detects proxy-logged HTTP requests to the four known exfiltration paths on `1688360[.]cc`: `/track.js`, `/card.php`, `/hit.php`, and `/html2canvas.min.js`.

**Rule 3: iOS Exploit Kit Delivery Path**  
File: `sigma_optimjack_ios_exploit.yml`  
Compile status: Passes `sigma convert` to Splunk and LogScale  
Confidence: HIGH for `.icu` domain matches; MEDIUM for path-only matches (paths like `/boot.js` are generic without domain context)

Detects proxy-logged requests to known iOS exploit delivery domains and paths used by the Coruna and DarkSword exploit kits.

### Suricata Rules (14 rules, SID 2200001-2200014)

File: `suricata_optimjack.rules`  
Compile status: Passes `suricata -T` validation (Suricata 7.0.3)  
Confidence: HIGH for domain-specific rules; MEDIUM for path-pattern rules

Covers DNS queries for C2 domains, HTTP requests to payload/exfiltration endpoints, TLS SNI detection for `1688360[.]cc`, iOS boot.js loader requests, JIUJIU888 exploit paths, and Coruna telemetry POSTs.

### Snort Rules (9 rules, SID 2100001-2100009)

File: `snort_optimjack.rules`  
Compile status: Syntax validated (Snort 2.9.20); full config test blocked by environment constraints  
Confidence: HIGH for domain+path combination rules; MEDIUM for DNS-encoded rules

Covers HTTP requests to track.js/card.php/hit.php on `1688360[.]cc`, webshell[.]lol/get.js, boot.js on .icu domains, JIUJIU888 paths, and DNS queries for primary domains.

### YARA Rules (5 rules)

File: `yara_optimjack.yar`  
Compile status: Passes `yarac` compilation (YARA 4.5.0)  
Confidence: HIGH for hash and wallet/domain rules; MEDIUM for behavioral pattern rules

| Rule | Description |
|------|-------------|
| `OPTIMJACK_TrackJS_Payload` | Matches track.js payload by domain references, global variables, or attacker wallet addresses |
| `OPTIMJACK_Loader_ProjectJS` | Matches OPTIMJACK loader code injected into Optimizely Project JavaScript, including .icu domains and obfuscated loader patterns |
| `OPTIMJACK_iOS_ExploitKit_Loader` | Matches iOS exploit kit loader (boot.js) by exploit paths, channel identifiers, and .icu domains |
| `OPTIMJACK_CardSkimmer_Behavior` | Behavioral detection of card skimming patterns: sendBeacon + card.php, html2canvas + hit.php, sessionStorage cc_ prefixes |
| `OPTIMJACK_TrackJS_SHA256` | Hash-based detection of four known track.js builds |

---

## Sources

- [Krebs on Security - Attackers Used Optimizely to A/B Test Malware on Top Websites](https://krebsonsecurity.com/2026/11/attackers-used-optimizely-to-a-b-test-malware-on-top-websites/)
- [Unit42 - Borrowed Code, Real Consequences: What OPTIMJACK Teaches Us](https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/)
- [ReversingLabs - OPTIMJACK: When Trusted JavaScript Becomes a Supply Chain Attack](https://www.reversinglabs.com/blog/optimjack-when-trusted-javascript-becomes-a-supply-chain-attack)
- [Phoenix Security - OPTIMJACK Optimizely Supply Chain Attack Card Skimmer iOS](https://phoenix.security/optimjack-optimizely-supply-chain-attack-card-skimmer-ios/)
- [StepSecurity - OPTIMJACK: Optimizely-Hosted Scripts, Crypto Clipper, Card Skimmer](https://www.stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer)
- [Zscaler - Attackers Exploit Optimizely Flaw to Inject Malicious JavaScript](https://www.zscaler.com/blogs/security-research/attackers-exploit-optimizely-flaw-inject-malicious-javascript)
- [Deepwatch - CA-26-048: OPTIMJACK Supply Chain Attack](https://www.deepwatch.com/labs/ca-26-048-optimjack-optimizely-web-experimentation-supply-chain-attack/)
- [Cloud Security Alliance - CSA Research Note: OPTIMJACK](https://labs.cloudsecurityalliance.org/research/csa-research-note-optimjack-optimizely-script-supply-chain-2/)

---

*This is a DRAFT report. IOCs should be validated against your environment before deploying blocking rules. Detection rules carry experimental status and should be tested in monitor-only mode before enforcement.*
