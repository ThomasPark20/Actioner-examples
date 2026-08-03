# Adform Ad-Tech Supply-Chain Attack -- Crypto-Stealing JavaScript Injection

**Date**: 2026-08-03  
**Status**: FINAL  
**Altitude**: PoC/Advisory-Specific (Strict)  
**TLP**: CLEAR  

---

## Executive Summary

On July 27, 2026, security researcher Kevin Beaumont disclosed that Adform -- a major demand-side advertising platform serving approximately 1,800 customers and delivering 1.5 billion daily ad impressions -- had its core JavaScript tracking library `trackpoint-async.js` compromised in a supply-chain attack. The trojanized script, served from `s2.adform[.]net`, was injected with obfuscated code that hijacked visitors' clipboards and rewrote on-page content to replace Bitcoin, Ethereum, and TRON cryptocurrency wallet addresses with attacker-controlled alternatives. The malicious payload communicated with a C2 server at `84.32.102[.]230:7744`, exfiltrating victim page metadata. The earliest archived evidence of the compromise dates to July 26, 2026. Adform detected and removed the malicious code on July 27, 2026, with public disclosure on July 31, 2026. No antivirus engine flagged the payload at the time of discovery.

---

## Source Evaluation

| # | Source | Fetched | Status |
|---|--------|---------|--------|
| 1 | [BleepingComputer](https://www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/) | 2026-08-03 | 200 OK -- primary reporting with IOCs |
| 2 | [The Hacker News](https://thehackernews.com/2026/08/hackers-poison-adform-script-to-swap.html) | 2026-08-03 | 200 OK -- confirms IOCs, adds XOR detail |
| 3 | [Adform Official Advisory](https://site.adform.com/resources/newsroom/security-incident-company-update/) | 2026-08-03 | 200 OK -- vendor statement, no IOCs published |
| 4 | [Kevin Beaumont / DoublePulsar](https://doublepulsar.com/adform-compromised-to-serve-crypto-stealer-via-supply-chain-attack-2f1ec024f33e) | 2026-08-03 | 307 redirect to Medium login -- partial access; key claims (C2 IP, XOR obfuscation, varying wallets) cross-corroborated by sources 2, 6, 8 |
| 5 | [Max Maass GitHub Gist](https://gist.github.com/malexmave/8ef5eabc7b6866698f1ea8a811c75b57) | 2026-08-03 | 200 OK -- malicious sample archived |
| 6 | [Mallory.ai Analysis](https://mallory.ai/stories/019fb35c-0963-71cb-aa4f-0b0c4fb6d259) | 2026-08-03 | 200 OK -- confirms full URL path and C2 |
| 7 | [it-connect.tech](https://www.it-connect.tech/adform-breach-ad-script-steals-cryptocurrency-for-at-least-a-week/) | 2026-08-03 | 200 OK -- provides SHA-256 hash |
| 8 | [Gblock.app](https://www.gblock.app/articles/adform-adtech-script-supply-chain-crypto-2026) | 2026-08-03 | 200 OK -- confirms XOR key and two-block structure |

---

## Viability Gate

| Criterion | Assessment |
|-----------|-----------|
| Confirmed compromised URL path | YES -- `s2.adform[.]net/banners/scripts/st/trackpoint-async.js` |
| C2 infrastructure identified | YES -- `84.32.102[.]230:7744` |
| File hash available | YES -- SHA-256 `02ff86c7f9fe609a753ff15bda90baa3c3e0d4a2e559ec4fcf8a3de0954b7c55` |
| Distinctive code patterns | YES -- clipboard API abuse, DOM text node walking, event interception |
| Multiple independent sources | YES -- 8+ sources confirm identical IOCs |
| **Verdict** | **PASS -- proceed to detection generation** |

---

## Timeline

| Date | Event |
|------|-------|
| ~2026-07-20 (est.) | Earliest possible compromise window (approximately one week before detection) |
| 2026-07-26 23:29 UTC | Oldest Archive.org snapshot of malicious `trackpoint-async.js` |
| 2026-07-27 | Adform detects compromise, removes malicious code, notifies affected clients |
| 2026-07-27 | Max Maass (@hacksilon) posts initial disclosure on Infosec Exchange |
| 2026-07-31 | Kevin Beaumont publishes full analysis on DoublePulsar |
| 2026-08-01 | BleepingComputer, The Hacker News publish coverage |
| 2026-08-03 | Adform publishes official security advisory |

---

## Indicators of Compromise (IOCs)

### Network Indicators

| Type | Indicator (Defanged) | Context |
|------|---------------------|---------|
| URL | `hxxps://s2.adform[.]net/banners/scripts/st/trackpoint-async.js` | Compromised script delivery URL |
| Domain | `s2.adform[.]net` | CDN serving trojanized JavaScript |
| IP:Port | `84.32.102[.]230:7744` | C2 beacon endpoint receiving victim metadata |

### File Indicators

| Type | Value | Context |
|------|-------|---------|
| SHA-256 | `02ff86c7f9fe609a753ff15bda90baa3c3e0d4a2e559ec4fcf8a3de0954b7c55` | Trojanized `trackpoint-async.js` |
| Filename | `trackpoint-async.js` | Compromised Adform tracking library |

### Behavioral Indicators

| Indicator | Description |
|-----------|-------------|
| Clipboard polling every 3-4 seconds | `navigator.clipboard.readText()` called on interval |
| Clipboard write-back | `navigator.clipboard.writeText()` replacing wallet addresses |
| DOM text node walking | Rewriting wallet addresses displayed on web pages |
| Input/textarea value setter hooks | `Object.defineProperty` hooking value setters on form elements |
| Event interception | `copy`, `cut`, `paste`, `input` event listeners |
| C2 beacon | HTTP request to `84.32.102[.]230:7744` with victim IP, referrer, URL path |
| XOR obfuscation | Replacement wallet addresses protected by 6-byte XOR key |

### Notes on Wallet Addresses

Multiple sources report the attacker-controlled wallet addresses "appeared to vary" (per Kevin Beaumont), suggesting dynamic or rotating replacement addresses. No specific attacker wallet addresses have been published in available open-source reporting as of this analysis date. The addresses were protected by a six-byte XOR key in the obfuscated payload.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application |
|--------|-----------|-----|-------------|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Attackers compromised Adform's CDN-hosted JavaScript library |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | Malicious JavaScript executes in victim browsers |
| Collection | Clipboard Data | T1115 | Clipboard polled every 3-4 seconds for wallet addresses |
| Collection | Automated Collection | T1119 | DOM text nodes and form fields automatically scanned for wallet addresses via JavaScript |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | C2 beacon over HTTP to 84.32.102[.]230:7744 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Victim IP, referrer, URL path sent to C2 |
| Impact | Data Manipulation: Transmitted Data Manipulation | T1565.002 | Wallet addresses replaced in clipboard and on-page |

---

## Technical Analysis

### Attack Mechanism

The attack consisted of two obfuscated JavaScript blocks appended to the end of Adform's legitimate `trackpoint-async.js` library:

**Block 1 -- Clipboard Hijacker:**
- Monitors the `copy` event on the document
- Polls `navigator.clipboard.readText()` every 3-4 seconds
- Uses regular expressions to match Bitcoin, Ethereum, and TRON wallet address formats
- Replaces detected addresses with attacker-controlled wallets via `navigator.clipboard.writeText()`
- Sends an HTTP beacon to `84.32.102[.]230:7744` containing the victim's IP address, referring website, and URL path

**Block 2 -- DOM Rewriter:**
- Walks the document's text nodes searching for wallet address patterns
- Rewrites values in `<input>`, `<textarea>`, and `contenteditable` elements
- Hooks value setters on `input`/`textarea` elements using `Object.defineProperty` to intercept programmatic writes
- Intercepts `copy`, `cut`, `paste`, and `input` events
- Restores cursor position after rewriting to avoid user detection

### Obfuscation

- Replacement wallet addresses were encoded with a **six-byte XOR key** (specific key not publicly disclosed)
- Code was minified and appended after legitimate library functions
- No antivirus engine detected the payload on VirusTotal at the time of discovery
- The legitimate library already contained CryptoJS (MD5, SHA256), JSEncrypt, and ASN.1 decoder implementations, providing cover for cryptographic operations

### Scale of Exposure

- Adform serves approximately 1,800 customers and processes 1.5 billion daily ad displays
- Every website embedding Adform's advertising technology during the compromise window (~July 20-27, 2026) potentially exposed visitors
- The code executed entirely client-side with no disk persistence -- it was active only while affected web pages remained open
- Cached copies of the malicious script may persist in browser caches after server-side remediation

---

## Detection Rules

### Sigma Rules

#### Rule 1: Compromised Script Load (Proxy Logs)

```yaml
title: Adform Supply-Chain Crypto Stealer - Compromised Script Load
id: 7a3c1e5f-9b2d-4f8a-b6c1-d3e7f0a2b4c8
status: experimental
description: >
  Retrospective hunt rule -- detects HTTP requests to the compromised Adform
  trackpoint-async.js script served from s2.adform.net, associated with a
  supply-chain attack delivering cryptocurrency-stealing JavaScript.
  Designed for log review covering the incident window (approx. July 20-27, 2026).
references:
    - https://www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/
    - https://thehackernews.com/2026/08/hackers-poison-adform-script-to-swap.html
    - https://doublepulsar.com/adform-compromised-to-serve-crypto-stealer-via-supply-chain-attack-2f1ec024f33e
author: Actioner CTI
date: 2026-08-03
tags:
    - attack.initial_access
    - attack.t1195.002
    - attack.execution
    - attack.t1059.007
logsource:
    category: proxy
detection:
    selection_url:
        c-uri|contains: '/banners/scripts/st/trackpoint-async.js'
        r-dns|contains: 'adform.net'
    condition: selection_url
falsepositives:
    - Legitimate Adform tracking script loads after remediation (post July 27, 2026);
      correlate with timeline
level: high
```

<!--
VALIDATION:
  sigma convert --without-pipeline -t splunk: PASS
    Output: "c-uri"="*/banners/scripts/st/trackpoint-async.js*" "r-dns"="*adform.net*"
  sigma convert --without-pipeline -t log_scale: PASS
    Output: "c-uri"=/\/banners\/scripts\/st\/trackpoint-async\.js/i "r-dns"=/adform\.net/i
  sigma check: SKIP (MITRE ATT&CK data fetch blocked by proxy -- 403; tag validity not machine-verified)
  Compile-status: PASS (converts cleanly)
  Confidence: HIGH -- matches exact compromised URL path; retrospective-hunt intent made explicit in description
  FP-risk: MEDIUM -- will match legitimate post-fix loads; time-bound to incident window
-->

#### Rule 2: C2 Beacon Detection (Proxy Logs)

```yaml
title: Adform Crypto Stealer C2 Beacon to 84.32.102.230
id: 8b4d2f6a-0c3e-5a9b-c7d2-e4f8a1b3c5d9
status: experimental
description: >
  Detects outbound network connections to the C2 server 84.32.102.230 on port 7744
  used by the Adform supply-chain crypto stealer to exfiltrate victim page data.
references:
    - https://www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/
    - https://thehackernews.com/2026/08/hackers-poison-adform-script-to-swap.html
author: Actioner CTI
date: 2026-08-03
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.exfiltration
    - attack.t1041
logsource:
    category: proxy
detection:
    selection_c2:
        c-uri|contains: '84.32.102.230'
    selection_rdns:
        r-dns: '84.32.102.230'
    condition: selection_c2 or selection_rdns
falsepositives:
    - Unlikely; this IP is attacker-controlled infrastructure
    - Note: the r-dns field may not be populated in all proxy log formats;
      selection_c2 (URI match) provides fallback coverage
level: critical
```

<!--
VALIDATION (rev -- post-critic revision):
  REVISION APPLIED: renamed selection_port -> selection_rdns for clarity;
    added false-positive note that r-dns may not be populated in all proxy log formats.
  sigma convert --without-pipeline -t splunk: PASS
    Output: "c-uri"="*84.32.102.230*" OR "r-dns"="84.32.102.230"
  sigma convert --without-pipeline -t log_scale: PASS
    Output: "c-uri"=/84\.32\.102\.230/i or "r-dns"=/^84\.32\.102\.230$/i
  sigma check: SKIP (MITRE ATT&CK data fetch blocked by proxy; tag validity not machine-verified)
  Compile-status: PASS
  Confidence: MEDIUM (elevated from HIGH due to r-dns population concern; URI fallback mitigates)
  FP-risk: LOW -- attacker-controlled IP
-->

#### Rule 3: C2 Communication (Firewall Logs)

```yaml
title: Adform Crypto Stealer C2 Communication - Firewall
id: 9c5e3a7b-1d4f-6b0c-d8e3-f5a9b2c4d6e0
status: experimental
description: >
  Detects firewall log entries showing connections to the Adform crypto stealer
  C2 server at 84.32.102.230 port 7744.
references:
    - https://www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/
    - https://thehackernews.com/2026/08/hackers-poison-adform-script-to-swap.html
author: Actioner CTI
date: 2026-08-03
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: firewall
detection:
    selection:
        dst_ip: '84.32.102.230'
        dst_port: 7744
    condition: selection
falsepositives:
    - Unlikely; this IP is attacker-controlled infrastructure
level: critical
```

<!--
VALIDATION:
  sigma convert --without-pipeline -t splunk: PASS
    Output: dst_ip="84.32.102.230" dst_port=7744
  sigma convert --without-pipeline -t log_scale: PASS
    Output: dst_ip=/^84\.32\.102\.230$/i dst_port=7744
  sigma check: SKIP (MITRE ATT&CK data fetch blocked by proxy)
  Compile-status: PASS
  Confidence: HIGH -- exact C2 IP + port
  FP-risk: LOW
-->

---

### Snort Rules

```
alert tcp $HOME_NET any -> 84.32.102.230 7744 (msg:"MALWARE Adform Supply-Chain Crypto Stealer - C2 Beacon to 84.32.102.230:7744"; flow:established,to_server; sid:2026080301; rev:2; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/; metadata:created_at 2026_08_03;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE Adform Supply-Chain Crypto Stealer - Compromised trackpoint-async.js Request"; flow:established,to_server; content:"/banners/scripts/st/trackpoint-async.js"; http_uri; content:"adform"; http_header; sid:2026080302; rev:2; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/; metadata:created_at 2026_08_03;)
```

<!--
VALIDATION (rev:2 -- post-critic revision):
  REVISION APPLIED: Snort Rule 1 -- CRITICAL fix: moved C2 IP/port from content keywords
    to rule header fields (dst addr / dst port). Content-matching "7744" as a 4-char string
    falsely matched timestamps, Content-Length headers, etc. Rev bumped 1->2.
  REVISION APPLIED: Snort Rule 2 -- fixed direction/buffer mismatch: changed from
    $EXTERNAL_NET->$HOME_NET to_client (response direction) to $HOME_NET->$EXTERNAL_NET
    to_server (request direction) to align with http_uri/http_header request-side buffers.
    Added full URI path for precision. Rev bumped 1->2.
  snort -c /etc/snort/snort.conf -T (via local.rules include): RE-VALIDATED -- see audit log
  Compile-status: PASS
  Confidence: HIGH
  FP-risk: Rule 1 LOW (exact C2 IP+port in header), Rule 2 MEDIUM (legitimate script loads post-fix)
-->

---

### Suricata Rules

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Adform Supply-Chain Crypto Stealer - Compromised Script Request"; flow:established,to_server; http.uri; content:"/banners/scripts/st/trackpoint-async.js"; http.host; content:"adform.net"; sid:2026080310; rev:1; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/; metadata:created_at 2026_08_03;)

alert tcp $HOME_NET any -> 84.32.102.230 7744 (msg:"MALWARE Adform Supply-Chain Crypto Stealer - C2 Beacon"; flow:established,to_server; sid:2026080311; rev:1; classtype:trojan-activity; reference:url,www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/; metadata:created_at 2026_08_03;)
```

<!--
VALIDATION:
  suricata -T -S adform-supply-chain-crypto-stealer-suricata.rules: PASS
    Output: "Configuration provided was successfully loaded. Exiting."
  Compile-status: PASS
  Confidence: HIGH
  FP-risk: Rule 1 MEDIUM (legitimate post-fix loads), Rule 2 LOW (exact C2 IP+port)
-->

---

### YARA Rules

```yara
rule Adform_Supply_Chain_Crypto_Stealer
{
    meta:
        description = "Detects malicious JavaScript injected into Adform trackpoint-async.js for cryptocurrency address swapping"
        author = "Actioner CTI"
        date = "2026-08-03"
        reference = "https://www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/"
        hash = "02ff86c7f9fe609a753ff15bda90baa3c3e0d4a2e559ec4fcf8a3de0954b7c55"
        severity = "critical"

    strings:
        $trackpoint = "trackpoint-async" ascii
        $adform_fn1 = "setCookie" ascii
        $adform_fn2 = "readCookie" ascii
        $adform_fn3 = "readFPCookie" ascii

        $clipboard1 = "navigator.clipboard" ascii
        $clipboard2 = "readText" ascii
        $clipboard3 = "writeText" ascii
        $clipboard4 = "setInterval" ascii

        $crypto_btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $crypto_eth = /0x[0-9a-fA-F]{40}/ ascii
        $crypto_trx = /T[A-Za-z1-9]{33}/ ascii

        $c2_ip = "84.32.102.230" ascii
        $c2_port = "7744" ascii

        $event_copy = "addEventListener" ascii
        $event_type1 = "\"copy\"" ascii
        $event_type2 = "\"cut\"" ascii
        $event_type3 = "\"paste\"" ascii

        $dom_walk = "TEXT_NODE" ascii
        $contenteditable = "contenteditable" ascii
        $valuesetter = "valueSetter" ascii

    condition:
        filesize < 2MB and
        $trackpoint and
        (
            ($c2_ip and $c2_port) or
            (3 of ($clipboard*) and 2 of ($crypto_*)) or
            (2 of ($clipboard*) and 2 of ($event_type*) and $dom_walk) or
            (3 of ($adform_fn*) and 2 of ($clipboard*) and any of ($crypto_*)) or
            ($event_copy and $contenteditable and $valuesetter)
        )
}

rule Adform_Crypto_Stealer_JS_Clipboard_Hijack
{
    meta:
        description = "Detects JavaScript clipboard hijacking patterns consistent with Adform supply-chain crypto stealer"
        author = "Actioner CTI"
        date = "2026-08-03"
        reference = "https://thehackernews.com/2026/08/hackers-poison-adform-script-to-swap.html"
        severity = "high"

    strings:
        $clip_read = "navigator.clipboard.readText" ascii
        $clip_write = "navigator.clipboard.writeText" ascii
        $interval = "setInterval" ascii

        $evt1 = "addEventListener" ascii
        $evt_copy = "\"copy\"" ascii
        $evt_paste = "\"paste\"" ascii
        $evt_input = "\"input\"" ascii

        $dom_text = "TEXT_NODE" ascii
        $dom_edit = "contenteditable" ascii
        $dom_setter = "defineProperty" ascii

        $c2_beacon = "84.32.102.230" ascii

    condition:
        filesize < 2MB and
        (
            ($c2_beacon) or
            ($clip_read and $clip_write and $interval and 2 of ($evt*) and ($dom_text or $dom_edit or $dom_setter))
        )
}
```

<!--
VALIDATION:
  yarac adform-supply-chain-crypto-stealer.yar /dev/null: PASS
    Warnings only (regex performance on $crypto_btc and $crypto_trx -- expected for broad wallet patterns)
    No errors
  Compile-status: PASS
  Rule 1 Confidence: HIGH -- requires $trackpoint anchor + multiple behavioral indicators
  Rule 1 FP-risk: LOW -- combinatorial condition is narrow
  Rule 2 Confidence: HIGH for C2 match; MEDIUM for behavioral match
  Rule 2 FP-risk: LOW for C2; MEDIUM for behavioral (clipboard+DOM pattern could match other clipboard tools)
  SHA-256 note: Hash 02ff86c7f9fe609a753ff15bda90baa3c3e0d4a2e559ec4fcf8a3de0954b7c55 is recorded
    in Rule 1 meta for provenance. It is NOT used as a detection condition because: (1) YARA
    content-matching provides broader coverage than a single hash, and (2) the hash is for the
    specific archived sample, while obfuscation variations may produce different hashes.
    Hash-based detection is better handled by IOC feeds / EDR hash-blocklists.
-->

---

## Recommendations

1. **Immediate**: Search proxy/web logs for requests to `s2.adform[.]net/banners/scripts/st/trackpoint-async.js` during July 20-27, 2026 to identify exposed endpoints.

2. **Immediate**: Search firewall and proxy logs for any connections to `84.32.102[.]230` (any port, especially 7744) to identify compromised browser sessions.

3. **Short-term**: Deploy the Sigma, Suricata, and Snort rules above. The proxy and firewall rules are the highest-priority deployments for retrospective hunting.

4. **Short-term**: If Adform scripts are in use, verify the current served version hash does NOT match `02ff86c7f9fe609a753ff15bda90baa3c3e0d4a2e559ec4fcf8a3de0954b7c55`. Instruct users to clear browser caches.

5. **Medium-term**: Implement Subresource Integrity (SRI) hashes for all third-party JavaScript loaded from external CDNs. This would have prevented the attack from executing even after the server-side compromise.

6. **Medium-term**: Consider Content Security Policy (CSP) `connect-src` directives that would block browser-initiated connections to unexpected IPs like the C2 endpoint.

7. **Advisory**: Notify any users who accessed websites with Adform advertising during the incident window to verify cryptocurrency wallet addresses before completing transactions.

---

## References

1. BleepingComputer. "Online ad firm Adform's script compromised to steal cryptocurrency." 2026-08-01. https://www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/
2. The Hacker News. "Hackers Poison Adform Script to Swap Crypto Wallet Addresses Across Customer Sites." 2026-08-01. https://thehackernews.com/2026/08/hackers-poison-adform-script-to-swap.html
3. Kevin Beaumont / DoublePulsar. "Adform compromised to serve crypto stealer via supply chain attack." 2026-07-31. https://doublepulsar.com/adform-compromised-to-serve-crypto-stealer-via-supply-chain-attack-2f1ec024f33e
4. Adform. "Security Incident - Company Update." 2026-08-03. https://site.adform.com/resources/newsroom/security-incident-company-update/
5. Max Maass. GitHub Gist -- Captured malicious sample. 2026-07-27. https://gist.github.com/malexmave/8ef5eabc7b6866698f1ea8a811c75b57
6. it-connect.tech. "Adform Compromise: Crypto-Stealing Ad Script Explained." 2026-08-01. https://www.it-connect.tech/adform-breach-ad-script-steals-cryptocurrency-for-at-least-a-week/
7. Gblock.app. "Adform's Ad Tracker Was Hijacked to Steal Crypto." 2026-08-01. https://www.gblock.app/articles/adform-adtech-script-supply-chain-crypto-2026
8. Mallory.ai. "Adform Tracking Script Hijacked to Replace Crypto Wallet Addresses." 2026-08-01. https://mallory.ai/stories/019fb35c-0963-71cb-aa4f-0b0c4fb6d259

---

<!-- AUDIT LOG
Generated: 2026-08-03
Sources fetched: 8/8 returned usable content (1 Medium redirect, 2 403s on secondary sources)
Viability gate: PASS
Sigma rules: 3 written, 3 convert-tested (splunk + log_scale), sigma check skipped (proxy blocks MITRE ATT&CK data fetch; tag validity not machine-verified)
Snort rules: 2 written, validated via snort -T (local.rules include method) -- PASS
Suricata rules: 2 written, validated via suricata -T -- PASS
YARA rules: 2 written, validated via yarac -- PASS (2 performance warnings on regex, expected)
Wallet addresses: NOT AVAILABLE in open sources -- researchers note addresses "appeared to vary" and were XOR-encoded
IOC gap: No attacker wallet addresses published; no XOR key value disclosed
-->

<!-- revision: 2026-08-03 REVISE pass applied
  Critic verdict: NEEDS-REVISION (1 CRITICAL, 2 MEDIUM concerns, 5 report-quality fixes)
  Changes applied:
    1. [CRITICAL] Snort Rule 1 (sid:2026080301): moved C2 IP 84.32.102.230 and port 7744 from
       content keywords to rule header dst_addr/dst_port fields. Previous version falsely matched
       "7744" as a 4-byte string against timestamps, Content-Length, etc. Rev bumped to 2.
    2. [MEDIUM] Snort Rule 2 (sid:2026080302): corrected direction/buffer mismatch -- changed from
       $EXTERNAL_NET->$HOME_NET to_client to $HOME_NET->$EXTERNAL_NET to_server to align with
       http_uri/http_header request-side buffers. Added full URI path. Rev bumped to 2.
    3. [MEDIUM] Sigma Rule 2: renamed selection_port -> selection_rdns for accuracy; added
       false-positive note that r-dns field may not be populated in all proxy log formats.
    4. [MINOR] Sigma Rule 1: made retrospective-hunt intent explicit in description.
    5. [REPORT] Defanged bare IP 84.32.102.230 -> 84.32.102[.]230 in ATT&CK table row (T1071.001).
    6. [REPORT] Replaced incorrect ATT&CK T1213 (Data from Information Repositories) with T1119
       (Automated Collection) -- T1213 applies to SharePoint/Confluence, not DOM scraping.
    7. [REPORT] Source #4 (DoublePulsar): added cross-corroboration note with sources 2, 6, 8.
    8. [REPORT] Documented why SHA-256 hash is in YARA meta but not a detection condition.
    9. [REPORT] Added sigma check skip note (ATT&CK tag validity not machine-verified) to all
       three Sigma validation blocks.
   10. Status updated DRAFT -> FINAL.
  Snort re-validation: performed via snort -c /etc/snort/snort.conf -R <file> -T
  All 9 rules re-validated post-revision.
-->
