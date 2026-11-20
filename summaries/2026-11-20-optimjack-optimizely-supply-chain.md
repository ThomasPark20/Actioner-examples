# OPTIMJACK: Optimizely Web Experimentation Supply Chain Attack

| Field | Value |
|---|---|
| **Threat Name** | OPTIMJACK |
| **Date** | 2026-11-16 (active 04:21 -- ~23:11 UTC) |
| **Vendor Compromised** | Optimizely (Web Experimentation platform) |
| **Victims** | 178+ organizations, 188 snippets confirmed |
| **Status** | DRAFT |
| **Last Updated** | 2026-11-20 |

---

## Executive Summary

On November 16, 2026, an attacker exploited a vulnerability in Optimizely's Web Experimentation account signup flow to inject malicious JavaScript into customer project snippets. The tampered code was served from Optimizely's legitimate CDN (cdn[.]optimizely[.]com) under its valid TLS certificate, reaching visitors of at least 178 major organizations including BBC, CNN, Zoom, Salesforce, GitLab, IKEA, HSBC, and Equifax. The multi-stage payload performed cryptocurrency wallet address swapping, payment card skimming, cookie/screenshot theft, and attempted to deliver iOS exploit kits (Coruna and DarkSword) to iPhones and iPads. Optimizely identified the incident the same day and deployed a fix within three hours, with full cleanup completed early November 17. Report URI estimated approximately $7,040 in cryptocurrency was stolen, plus an unknown number of payment card records.

---

## Sources

| # | Source | URL | Status |
|---|---|---|---|
| 1 | Unit 42 (Palo Alto Networks) | [OPTIMJACK Supply Chain Attack](https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/) | Verified |
| 2 | KrebsOnSecurity | [Attackers Used Optimizely to A/B Test Malware on Top Websites](https://krebsonsecurity.com/2026/11/attackers-used-optimizely-to-a-b-test-malware-on-top-websites/) | Verified |
| 3 | The Hacker News | [Hijacked Optimizely Scripts Served Card Skimmer](https://thehackernews.com/2026/11/hijacked-optimizely-scripts-served-card.html) | Verified |
| 4 | Report URI | [World's Largest Brands Infected with Malware via Optimizely](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/) | Verified |
| 5 | ThreatDefence | [Optimizely Web Experimentation Malicious JavaScript Hunting](https://threatdefence.com/article/optimizely-web-experimentation-malicious-javascript-hunting) | Verified |
| 6 | Optimizely Status Page | [Web Experimentation Security Incident](https://status.optimizely.com/incidents/ftw0fh9wx43z) | Verified |

---

## Timeline

| Time (UTC) | Event |
|---|---|
| Sep 17 | Injector first observed on Turkish sites via earlier campaign |
| Late previous week | Same injector planted via Kissmetrics, StorifyMe, and Minute Media scripts |
| Nov 9 | iOS exploit router domain 5vobauua3ojpklx[.]icu registered |
| Nov 16, 04:21 | First injection observed in BBC's Optimizely snippet; loads webshell[.]lol |
| Nov 16, 13:43 | Card skimmer component added to payload |
| Nov 16, 17:13 | Coruna iOS exploit iframe added for iOS 18.6 and earlier |
| Nov 16, 17:57 | Final track.js build deployed |
| Nov 16, 19:25 | Attacker wallets had received ~$7,040 |
| Nov 16, ~20:40 | Optimizely begins mass cleanup |
| Nov 16, 21:52 | Only TalkTalk snippet still carrying malicious code |
| Nov 17, 01:02 | Optimizely publishes incident notice; vulnerability patched |
| Nov 17 | Domain 1688360[.]cc suspended |
| Nov 18 | Optimizely publishes initial findings report (PDF) |

---

## Attack Mechanism

### Entry Point
The attacker exploited a vulnerability in Optimizely's Web Experimentation account signup flow to impersonate users on targeted customer accounts. This was not a credentials breach. Write access to the **Project JavaScript** field in customer projects allowed the attacker to inject loader code that would be served via Optimizely's CDN (`cdn[.]optimizely[.]com`) with a valid TLS certificate.

### Loader Variants
Three loader variants were observed:
1. **Direct script tag**: Loads `hxxps://1688360[.]cc/track.js` directly
2. **Base64-obfuscated**: Hides the URL using `atob()` to decode `aHR0cHM6Ly8xNjg4MzYwLmNjL3RyYWNrLmpz`, evading plaintext searches
3. **Embedded fallback**: Contains a full payload copy executed via `eval()` if the remote domain is blocked

### Payload Capabilities (track.js)
- **Cryptocurrency clipper**: Replaces wallet addresses (Bitcoin, Ethereum, TRON, Solana, TON, Litecoin, Bitcoin Cash, Dogecoin) with attacker-controlled addresses; validates checksums before swapping
- **Card skimmer** (added 13:43 UTC): Captures card number, expiry, and CVV from same-origin form fields; exfiltrates to `1688360[.]cc/card.php`. Does not read cross-origin payment iframes (Stripe, Adyen)
- **Cookie/screenshot theft**: Sends cookies and html2canvas screenshots to `1688360[.]cc/hit.php` after detecting payment-related activity. Cannot read HttpOnly cookies
- **iOS exploit delivery**: Loads `boot.js` from .icu domains; fingerprints iOS version and opens exploit chains in hidden iframes:
  - iOS 13-17: Coruna exploit kit (zero-click, ~23 exploits)
  - iOS 18.0-18.7: DarkSword exploit kit (~6 vulnerabilities)
  - iOS 26: Fingerprinting-only chain (no known exploit)
  - Pages reload every 60 seconds to retry exploit delivery

The payload was rebuilt 26 times during the active window, with markers `window._k7` and `window.__k7b` used as execution guards.

---

## Indicators of Compromise

> **Note**: IOCs in prose are defanged per convention. Detection rules below use real values.

### Domains

| Domain | Role |
|---|---|
| 1688360[.]cc | Primary C2; serves track.js, card.php, hit.php |
| webshell[.]lol | Injector (get.js), earlier wave |
| linkforge[.]cc | SEO-panel script carrying the injector (September) |
| 5vobauua3ojpklx[.]icu | iOS exploit router (boot.js) |
| eil786npto9u5bq[.]icu | iOS exploit router, Coruna and iOS 26 pages |
| l7bcsnwc7nzr3uo[.]icu | Coruna telemetry (POST /api/iptj) |
| je4ft3gn8vxudum[.]icu | Fallback C2 in boot.js |
| q1ls1ho9x7wsxlu[.]icu | Fallback C2 in boot.js |
| ios-hack[.]icu | Fallback C2 in boot.js |
| p55abnw2pnsz0bo[.]icu | Shared certificates with exploit kit |
| 1y69gy2mdzaltz1[.]icu | Shared certificates with exploit kit |
| gm38duxoihbmy5o[.]icu | Shared certificates with exploit kit |

### IP Addresses

| IP | Associated Domain | Note |
|---|---|---|
| 136.113.106[.]136 | 1688360[.]cc | Cloud-hosted; may be reassigned post-attack |
| 34.96.213[.]201 | 5vobauua3ojpklx[.]icu | Cloud-hosted; validate timestamps |
| 34.87.36[.]58 | eil786npto9u5bq[.]icu | Cloud-hosted; validate timestamps |

### File Hashes (SHA-256)

| Hash | File |
|---|---|
| `f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40` | track.js (final build, 17:57 UTC) |
| `814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f` | track.js (17:13 UTC build) |
| `c2a34c579e4c2e8802752c93b3a9cca0230610f3e4dd6688f4272459c7c7c162` | Embedded payload copy in loader |
| `123f813b18cf5a3b513beabd52a110e19f1c7834f2aa9b972633b2214c57e737` | webshell[.]lol/get.js |

### URL Paths

| URL | Purpose |
|---|---|
| /track.js | Main payload delivery |
| /card.php | Card data exfiltration (POST) |
| /hit.php | Cookie/screenshot exfiltration (POST) |
| /html2canvas.min.js | Screenshot library |
| /boot.js | iOS exploit router |
| /A8/, /JIUJIU888/index.js | Coruna chain (iOS 13-17) |
| /B9/, /D11/, /D12/ | DarkSword chain (iOS 18.x) |
| /C10/ | iOS 26 fingerprinting chain |
| /api/iptj | Coruna telemetry endpoint |

### JavaScript Markers

| Marker | Context |
|---|---|
| `window._k7` | Execution guard set by payload |
| `window.__k7b` | Secondary execution guard |
| `data-channel-code="02111110"` | iOS loader script-tag attribute |
| `BIGNIAO` | Coruna telemetry channel code |
| `atob(` | Base64-obfuscated loader variant |
| `aHR0cHM6Ly8xNjg4MzYw` | Base64 prefix of payload URL |
| `sessionStorage` keys with `cc_` prefix | Card skimmer state tracking |

### Attacker Cryptocurrency Wallets

| Chain | Address |
|---|---|
| BTC | `19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW` |
| ETH/EVM | `0xC4026b06D82b0F0B363eda0642D61CfbDc17884e` |
| TRON | `THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa` |
| SOL | `FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n` |
| TON | `UQAgM1VqSZQiJLSG5w-ovurq5CZdxLEK3_7CMmwALTA5e09p` |
| LTC | `ltc1q3wp7g6ds0ggg6fl6kncpa4sepn0q3qfacgred5` |
| BCH | `qzkaaf8n6grmpr0d9lx8xutn3r9lk722f566hhpe58` |
| DOGE | `DBEGrxRF7KMSuhTS4c1MFviStU6efdMnu5` |
| TRON (cash-out) | `TMLQvDvpgSyx94maptc3TxvmCVtT5qHVup` |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|---|---|---|
| Initial Access | T1195.002 - Compromise Software Supply Chain | Attacker injected malicious JS via Optimizely's platform |
| Execution | T1059.007 - JavaScript | Malicious JavaScript executed in victim browsers |
| Persistence | T1195.002 - Supply Chain Compromise | Payload served on every page load via compromised Optimizely CDN snippet; the supply chain injection is itself the persistence mechanism |
| Defense Evasion | T1027 - Obfuscated Files or Information | Base64-encoded loader variant using atob() |
| Defense Evasion | T1036 - Masquerading | Payload served from legitimate cdn[.]optimizely[.]com |
| Collection | T1185 - Browser Session Hijacking | Cookie theft and screenshot capture |
| Collection | T1056.003 - Web Portal Capture | Card skimmer captures payment form fields |
| Exfiltration | T1041 - Exfiltration Over C2 Channel | Card data, cookies, screenshots sent to 1688360[.]cc |
| Impact | T1565.002 - Transmitted Data Manipulation | Crypto wallet address replacement in forms and clipboard |

---

## Detection Rules

### Sigma Rules

#### 1. OPTIMJACK C2 Domain DNS Queries

**File**: `/tmp/actioner/optimjack_payload_domains.yml`

Detects DNS queries to any of the 12 known OPTIMJACK C2, payload delivery, iOS exploit router, and fallback domains. High confidence due to attacker-registered domains with no legitimate use.

| Property | Value |
|---|---|
| Compile status | sigma check: PASS, sigma convert splunk: PASS, sigma convert log_scale: PASS |
| Confidence | High |
| MITRE ATT&CK | T1195.002, T1071.001 |
| Log source | dns_query |

#### 2. OPTIMJACK Malicious URL Paths in Proxy Logs

**File**: `/tmp/actioner/optimjack_proxy_urls.yml`

Detects HTTP requests to specific OPTIMJACK payload URLs including track.js delivery, card.php exfiltration, and iOS boot.js router endpoints in web proxy logs. High confidence; these URL+host combinations are unique to the attack infrastructure.

| Property | Value |
|---|---|
| Compile status | sigma check: PASS, sigma convert splunk: PASS, sigma convert log_scale: PASS |
| Confidence | High |
| MITRE ATT&CK | T1195.002, T1041 |
| Log source | proxy |

#### 3. OPTIMJACK Known C2 IP Addresses

**File**: `/tmp/actioner/optimjack_c2_ips.yml`

Detects network connections to the three IP addresses resolved from OPTIMJACK C2 domains during the attack window. Caveat: these are cloud-hosted IPs that may be reassigned; validate matches against the Nov 9-17, 2026 timeframe.

| Property | Value |
|---|---|
| Compile status | sigma check: PASS, sigma convert splunk: PASS, sigma convert log_scale: PASS |
| Confidence | Medium |
| MITRE ATT&CK | T1071.001 |
| Log source | firewall |

### YARA Rules

#### 4. OPTIMJACK_TrackJS_Payload

**File**: `/tmp/actioner/optimjack_payload.yar` (rule 1 of 3)

Detects the OPTIMJACK track.js payload by matching C2 domains combined with known URL paths or execution markers, or the base64-encoded payload URL, or the iOS channel code with router domains. Useful for scanning cached JavaScript, proxy logs, or forensic disk images.

| Property | Value |
|---|---|
| Compile status | yarac: PASS (exit 0) |
| Confidence | High |
| Hashes covered | f7b84b9a...bad40, 814a963c...c3a0f |

#### 5. OPTIMJACK_Loader_Variants

**File**: `/tmp/actioner/optimjack_payload.yar` (rule 2 of 3)

Detects OPTIMJACK loader variants including direct URL references, base64-encoded URLs, embedded payload hashes, and the behavioral pattern of _k7 markers combined with atob/eval and createElement. Caveat: the behavioral branch (markers + atob + eval + createElement) may match other obfuscated JavaScript loaders at lower confidence.

| Property | Value |
|---|---|
| Compile status | yarac: PASS (exit 0) |
| Confidence | High (IOC branches) / Medium (behavioral branch) |
| Hash covered | 123f813b...e737 |

#### 6. OPTIMJACK_CryptoClipper_Wallets

**File**: `/tmp/actioner/optimjack_payload.yar` (rule 3 of 3)

Detects the specific cryptocurrency wallet addresses used by the OPTIMJACK attacker across 9 blockchain networks. Any match on these addresses in a JavaScript file or web traffic capture is a strong indicator of this campaign.

| Property | Value |
|---|---|
| Compile status | yarac: PASS (exit 0) |
| Confidence | High |

### Suricata/Snort Rules

#### 7-16. OPTIMJACK Network Detection Suite

**File**: `/tmp/actioner/optimjack_c2_network.rules`

16 rules covering DNS queries for 9 primary C2/exploit domains (rules 1-9), HTTP requests for specific payload/exfiltration paths on the primary C2 (rules 10-12), Coruna telemetry POST (rule 13), and direct IP connections (rules 14-16). Note: 3 shared-certificate domains (`p55abnw2pnsz0bo[.]icu`, `1y69gy2mdzaltz1[.]icu`, `gm38duxoihbmy5o[.]icu`) are covered by the Sigma DNS rule but not by Suricata DNS rules. Rules use Suricata-style sticky buffers (dns.query, http.uri, http.host, http.method). Caveat: IP-based rules (SIDs 2026111614-16) should be time-bounded to the attack window due to cloud IP reassignment risk.

| Property | Value |
|---|---|
| Compile status | Uncompiled (structural check only) |
| Confidence | High (domain/URL rules) / Medium (IP rules) |
| SID range | 2026111601 -- 2026111616 |

---

## CSP and Mitigation Context

Report URI analysis found that of the 178 affected organizations:
- 68 sites had **no Content Security Policy** at all
- 50 sites had a CSP that **still allowed** the payload and data exfiltration
- Only 24 sites (~15%) had a CSP that **fully blocked** the payload

Overall CSP adoption across the busiest sites is approximately 10% (per crawler.ninja / HTTP Archive 2025 Web Almanac).

### Recommended Defensive Actions

**For site owners using Optimizely:**
- Search Project JavaScript and experiment custom code for `1688360`, `atob(`, `webshell`, and unknown script sources
- Audit and rotate credentials for all users, API tokens, and integrations with write access
- Treat payment cards entered during the Nov 16 exposure window as potentially compromised
- Rotate secrets stored in cookies lacking the HttpOnly flag
- Deploy a strict CSP with explicit `script-src` and `connect-src` directives; note that `strict-dynamic` or `unsafe-eval` can permit the payload to execute
- Isolate payment collection in cross-origin iframes (Stripe hosted fields, Adyen, etc.)

**For visitors:**
- Update iOS to 18.7.3+ or 26.3+
- Compare cryptocurrency payments made Nov 16 against intended recipient addresses
- Monitor card statements if cards were used on affected sites

---

## Affected Sector Breakdown

| Sector | Count | Examples |
|---|---|---|
| Banking & Finance | 32 | HSBC, Equifax, ABN AMRO, Paychex |
| Technology & SaaS | 23 | Zoom, GitLab, Salesforce, Bitly, Smartsheet |
| Retail & Fashion | 20 | IKEA, ASOS, Mattel, American Eagle, Levi's |
| Streaming & Entertainment | 12 | Peacock, D&D Beyond, NOW TV |
| News & Media | 10 | CNN, BBC, Fox News, NPR |
| Airlines & Travel | 9 | Alaska/Hawaiian, Air France-KLM, Transavia |
| Healthcare & Pharma | 8 | Invisalign, Takeda |
| Industrial & Manufacturing | 8 | Fluke, Vaillant |
| Telecoms | 7 | Virgin Media, O2, Vodafone AU, TalkTalk |
| Crypto & Trading | 6 | Ledger, IG, OANDA |
| Insurance | 6 | Asurion, Mutual of Omaha, Admiral |
| Other sectors | 37 | Change.org, UNICEF USA, Lucid Motors, Starbucks CA |

---

## Open Questions

1. **Vulnerability details**: Optimizely has not disclosed the specific vulnerability class or assigned a CVE. The entry vector was described as the "account signup flow" but the precise mechanism enabling cross-account project access remains unexplained.
2. **Re-infection**: Smartsheet's snippet was re-infected after initial cleanup, suggesting the attacker retained access. It is unclear whether this has been fully resolved.
3. **Earlier campaign**: The same injector appeared on Turkish sites in September and was planted via Kissmetrics, StorifyMe, and Minute Media, indicating a broader supply chain campaign beyond Optimizely.
4. **iOS exploitation success**: Cynet described its observations as "not a successful compromise of a physical iPhone or iPad" (emulated environment). The real-world success rate of the Coruna/DarkSword chains against site visitors is unknown.
5. **Full victim enumeration**: 178 is a lower bound; not all Optimizely snippets were checked.

---

*Draft prepared 2026-11-20. All detection rules are in `/tmp/actioner/`. Sigma rules validated with `sigma check` and `sigma convert` (Splunk, LogScale). YARA rules compiled with `yarac`. Suricata/Snort rules are structural-only (compiler not available).*
