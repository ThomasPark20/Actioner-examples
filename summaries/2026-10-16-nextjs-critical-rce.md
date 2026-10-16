# Next.js Out-of-Band Patch for Two Critical RCE Flaws and High-Severity DoS

**Date:** 2026-10-16
**Status:** DRAFT
**Author:** Actioner
**Severity:** Critical (CVSS 9.5) / High (CVSS 8.2)

---

## Executive Summary

On October 14, 2026, Vercel shipped an out-of-band security update for Next.js addressing two critical unauthenticated remote code execution (RCE) vulnerabilities and one high-severity denial-of-service (DoS) flaw. The fixes landed in **Next.js 16.4.1** (Active LTS) and **15.5.28** (Maintenance LTS). These patches were originally delayed from the September 2026 security release due to upstream dependency fixes not being ready in time.

Next.js is one of the most widely deployed web frameworks, with an estimated 444,000+ publicly reachable servers. All three vulnerabilities are exploitable without authentication and affect the App Router, making this a high-priority patching event.

As of October 15, 2026, there are no confirmed reports of exploitation in the wild, and none of the CVEs appear in CISA's Known Exploited Vulnerabilities catalog.

---

## Vulnerabilities

### 1. Unauthenticated RCE in `use cache` Functions Returning Typed Arrays (Critical)

| Field | Value |
|---|---|
| **Advisory** | [GHSA-673q-mjm6-r5xr](https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr) |
| **CVE** | None assigned as of 2026-10-15 |
| **CVSS** | 9.5 (Critical) — CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N |
| **CWE** | Not listed |
| **Affected** | Next.js 16.0.0 through 16.4.0 |
| **Fixed** | Next.js 16.4.1 |
| **Upstream** | [GHSA-xqc2-xf4c-x3h3](https://github.com/react/react/security/advisories/GHSA-xqc2-xf4c-x3h3) (React) |
| **React Fix** | 19.0.9, 19.1.10, 19.2.9, 19.3.1 |
| **Credit** | evolutionstorm (finder) |

**Technical Details:**

The vulnerability resides in the React Server Components (RSC) Flight protocol, specifically in the `react-server-dom-webpack`, `react-server-dom-parcel`, and `react-server-dom-turbopack` packages (versions 19.0.0 through 19.3.0). The flaw is triggered when a `use cache` function returns multiple typed arrays and the response contains an attacker-controlled value. This is a deserialization vulnerability in the RSC Flight reply payload processing.

**Preconditions:**
- App Router with Cache Components enabled (`cacheComponents: true` in `next.config.js`)
- A `use cache` function that returns multiple typed arrays
- Next.js 16.x only (15.x is not affected by this specific flaw)

**Attack Vector:** Network (unauthenticated). Crafted HTTP requests exploiting the RSC Flight protocol.

**Workaround:** None. Upgrade is the only mitigation. Vercel advises upgrading even if no matching `use cache` functions exist in the application.

**Detection Gap:** This vulnerability has no CVE assigned and does not appear in the npm advisory feed, meaning `npm audit` will not flag it.

---

### 2. Unauthenticated RCE in Image Optimization API via SVG Processing (Critical)

| Field | Value |
|---|---|
| **Advisory** | [GHSA-2464-fhr4-w9xw](https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw) |
| **CVE** | [CVE-2026-96889](https://access.redhat.com/security/cve/cve-2026-96889) |
| **CVSS** | 9.5 (Critical, Vercel) / 7.8 (High, Red Hat — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) |
| **CWE** | CWE-416 (Use After Free) |
| **Affected** | Next.js 10.0.0 through 15.5.27; 16.0.0 through 16.4.0 |
| **Fixed** | Next.js 15.5.28 (with sharp >= 0.35.5), Next.js 16.4.1 |
| **Upstream** | [GHSA-wq5f-xc86-pv6w](https://github.com/advisories/GHSA-wq5f-xc86-pv6w) (sharp), librsvg < 2.63.2 |
| **Credit** | Rafael B. Dias (reporter) |

**Technical Details:**

This is a use-after-free vulnerability in **librsvg**, reachable through the **sharp** image processing library bundled with Next.js. The flaw is triggered when librsvg processes a specially crafted SVG document containing **nested XML inclusions (XIncludes) with duplicate entity declarations**. The parser incorrectly frees an XML entity that is still in use, resulting in a use-after-free condition that can lead to arbitrary code execution.

**Attack Surface:**
- **`/_next/image` endpoint** — The Next.js Image Optimization API. Requires `dangerouslyAllowSVG: true` in `next.config.js` (off by default).
- **`next/og` (ImageResponse)** — The Open Graph image generation component on the Node.js runtime. This path may be vulnerable even without `dangerouslyAllowSVG`.

**Preconditions:**
- Next.js running on **glibc-based Linux** (macOS, Windows, and musl-based Linux are not affected)
- For the `/_next/image` path: `dangerouslyAllowSVG` must be enabled
- For the `next/og` path: Node.js runtime (not Edge)
- A non-PIE Node.js binary (PIE binaries on some distributions may block exploitation)

**Request Pattern:**
The `/_next/image` endpoint accepts GET requests with query parameters:
- `url=` — The source image URL (must match configured `remotePatterns` or `localPatterns`)
- `w=` — Width (must match configured `deviceSizes` or `imageSizes`)
- `q=` — Quality (integer within configured range)

An attacker would need to supply a malicious SVG file accessible via the `url` parameter, either by hosting it remotely (if remote patterns are configured) or by uploading it to a local path.

**Workarounds:**
1. Upgrade `sharp` to 0.35.5 or later
2. Block SVG decoding: `sharp.block({ operation: ["VipsForeignLoadSvg"] })`
3. Disable `dangerouslyAllowSVG` if enabled (does not protect `next/og`)

**Important Lockfile Note:** On Next.js 15.x, upgrading to 15.5.28 may still resolve `sharp` 0.34.x if a lockfile pins that version. Verify with `npm ls sharp`.

---

### 3. Denial of Service in App Router Server Actions (High)

| Field | Value |
|---|---|
| **Advisory** | [GHSA-p3m5-59mp-jv5r](https://github.com/vercel/next.js/security/advisories/GHSA-p3m5-59mp-jv5r) |
| **CVE** | None assigned as of 2026-10-15 |
| **CVSS** | 8.2 (High) — CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N |
| **CWE** | Not listed |
| **Affected** | Next.js 13.0.0 through 15.5.27; 16.0.0 through 16.4.0 |
| **Fixed** | Next.js 15.5.28, 16.4.1 |
| **Upstream** | [GHSA-h3gv-c5rc-p453](https://github.com/react/react/security/advisories/GHSA-h3gv-c5rc-p453) (React) |

**Technical Details:**

Crafted HTTP requests targeting Next.js applications using the App Router with at least one Server Action can cause excessive CPU usage. The CPU exhaustion blocks processing of further requests in the same process, leading to denial of service.

**Preconditions:**
- App Router application with at least one Server Action
- Pages Router applications and apps without Server Actions are not affected

**Attack Vector:** Network (unauthenticated). Server Actions are invoked via HTTP POST requests carrying a `Next-Action` header with the action identifier. The specific crafted payload that triggers CPU exhaustion is not publicly documented.

**Workaround:** None. Upgrade is the only mitigation.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Relevance |
|---|---|---|
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | All three flaws target internet-facing Next.js applications without authentication |
| [T1203](https://attack.mitre.org/techniques/T1203/) | Exploitation for Client Execution | SVG processing and RSC deserialization lead to code execution on the server |
| [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | Command and Scripting Interpreter: JavaScript | Post-exploitation in the Node.js runtime environment |
| [T1499.003](https://attack.mitre.org/techniques/T1499/003/) | Endpoint Denial of Service: Application or System Exploitation | Server Actions CPU exhaustion DoS |

---

## Viability Gate Assessment

**SVG/Image Optimization RCE (CVE-2026-96889):** VIABLE for detection. The attack requires HTTP requests to known endpoints (`/_next/image`, OG image routes) with SVG content containing XInclude directives. The `/_next/image` endpoint, SVG content types, and XInclude patterns are detectable at the network layer.

**`use cache` RCE (GHSA-673q-mjm6-r5xr):** LIMITED viability. The exploitation occurs through the RSC Flight protocol deserialization layer. No specific HTTP request patterns, headers, or payload formats have been publicly documented. Detection must rely on version-based identification and anomaly detection rather than signature matching. No production-ready detection rule can be written for this flaw at this time.

**Server Actions DoS (GHSA-p3m5-59mp-jv5r):** PARTIAL viability. Server Actions use POST requests with the `Next-Action` header. High-frequency POST requests causing server errors (5xx) can be detected, but distinguishing DoS attempts from legitimate traffic requires threshold-based rules with acceptable false-positive rates.

---

## Detection Rules

### Sigma Rules

All Sigma rules validated with `sigma check` (0 errors) and successfully converted to Splunk SPL.

#### Rule 1: Next.js Image Optimization API SVG RCE Attempt

- **File:** `nextjs_svg_rce_image_optimization.yml`
- **ID:** `482d6c5a-b20e-49cd-8bc1-d780d3feac5a`
- **Compile status:** PASS
- **Confidence:** MEDIUM — Detects SVG requests to `/_next/image` but cannot distinguish malicious from legitimate SVGs without payload inspection
- **Level:** high
- **Logic:** Matches web server access logs where `cs-uri-stem` contains `/_next/image` AND `cs-uri-query` contains `.svg`, `image/svg`, or URL-encoded SVG content type

```yaml
title: Next.js Image Optimization API SVG RCE Attempt (CVE-2026-96889)
id: 482d6c5a-b20e-49cd-8bc1-d780d3feac5a
status: experimental
description: >
  Detects HTTP requests to the Next.js Image Optimization API endpoint
  (/_next/image) that reference SVG image sources. CVE-2026-96889 is a
  use-after-free in librsvg triggered by crafted SVG files with nested
  XIncludes and duplicate entity declarations, reachable through the
  sharp image processing library on glibc-based Linux. Requires
  dangerouslyAllowSVG to be enabled in next.config.js.
references:
  - https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw
  - https://nextjs.org/blog/nextjs-security-update-october-14-2026
  - https://access.redhat.com/security/cve/cve-2026-96889
  - https://thehackernews.com/2026/10/nextjs-ships-out-of-band-patch-for-two.html
author: Actioner
date: 2026/10/16
tags:
  - attack.t1190
  - attack.t1203
  - cve.2026.96889
logsource:
  category: webserver
  service: access
detection:
  selection_endpoint:
    cs-uri-stem|contains: '/_next/image'
  selection_svg:
    cs-uri-query|contains:
      - '.svg'
      - 'image/svg'
      - 'image%2Fsvg'
  condition: selection_endpoint and selection_svg
falsepositives:
  - Legitimate SVG image optimization requests in applications with dangerouslyAllowSVG enabled
  - Internal monitoring or health check tools accessing image endpoints
level: high
```

#### Rule 2: Next.js SVG XInclude Exploitation Attempt

- **File:** `nextjs_svg_xinclude_exploit_attempt.yml`
- **ID:** `0fbc88f6-cecc-45d5-9a84-424fc0e6e219`
- **Compile status:** PASS
- **Confidence:** HIGH — XInclude directives in SVG uploads are uncommon in legitimate traffic and directly correlate with the CVE-2026-96889 exploit trigger
- **Level:** high
- **Logic:** Matches web server logs where request content-type contains `svg` AND request body contains XInclude indicators

```yaml
title: Next.js SVG XInclude Exploitation Attempt (CVE-2026-96889)
id: 0fbc88f6-cecc-45d5-9a84-424fc0e6e219
status: experimental
description: >
  Detects HTTP request bodies or uploaded content containing SVG payloads
  with XInclude directives, which are the specific trigger for the
  use-after-free vulnerability in librsvg (CVE-2026-96889). The
  vulnerability is triggered when librsvg processes an SVG document
  containing nested XML inclusions (XIncludes) with duplicate entity
  declarations. This rule targets web server logs that capture request
  body content or POST data.
references:
  - https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw
  - https://nextjs.org/blog/nextjs-security-update-october-14-2026
  - https://access.redhat.com/security/cve/cve-2026-96889
author: Actioner
date: 2026/10/16
tags:
  - attack.t1190
  - attack.t1203
  - cve.2026.96889
logsource:
  category: webserver
  service: access
detection:
  selection_svg_header:
    cs-content-type|contains: 'svg'
  selection_xinclude:
    cs-body|contains:
      - 'xi:include'
      - 'XInclude'
      - 'xinclude'
      - 'http://www.w3.org/2001/XInclude'
  condition: selection_svg_header and selection_xinclude
falsepositives:
  - Legitimate SVG uploads that use XInclude for valid document composition
level: high
```

#### Rule 3: Next.js Server Actions Potential DoS

- **File:** `nextjs_server_actions_dos.yml`
- **ID:** `19fdf67d-193c-4f58-8747-404d5e639474`
- **Compile status:** PASS
- **Confidence:** LOW — Relies on error status codes correlating with POST requests; requires tuning per environment
- **Level:** medium
- **Logic:** Matches POST requests referencing Next.js internals that result in 5xx server errors

```yaml
title: Next.js Server Actions Potential DoS via Crafted Requests
id: 19fdf67d-193c-4f58-8747-404d5e639474
status: experimental
description: >
  Detects patterns indicative of denial-of-service attempts targeting
  Next.js Server Actions. The vulnerability (GHSA-p3m5-59mp-jv5r)
  allows crafted POST requests to App Router applications with Server
  Actions to cause excessive CPU usage, blocking processing of further
  requests. This rule looks for high-frequency POST requests with the
  Next-Action header from a single source, which may indicate
  exploitation attempts.
references:
  - https://github.com/vercel/next.js/security/advisories/GHSA-p3m5-59mp-jv5r
  - https://nextjs.org/blog/nextjs-security-update-october-14-2026
  - https://thehackernews.com/2026/10/nextjs-ships-out-of-band-patch-for-two.html
author: Actioner
date: 2026/10/16
tags:
  - attack.t1190
  - attack.t1499.003
logsource:
  category: webserver
  service: access
detection:
  selection_method:
    cs-method: 'POST'
  selection_action_header:
    cs-referer|contains: '_next'
  selection_status:
    sc-status:
      - 500
      - 502
      - 503
      - 504
  condition: selection_method and selection_action_header and selection_status
falsepositives:
  - Application errors unrelated to exploitation
  - Load testing or stress testing activities
level: medium
```

#### Rule 4: Next.js next/og ImageResponse SVG Injection Attempt

- **File:** `nextjs_nextog_svg_rce.yml`
- **ID:** `e471688b-38cc-4e95-a1b5-ec33f15a2c19`
- **Compile status:** PASS
- **Confidence:** MEDIUM — OG image endpoint paths vary by application; rule covers common patterns
- **Level:** medium
- **Logic:** Matches requests to common OG image endpoints with SVG-related query parameters

```yaml
title: Next.js next/og ImageResponse SVG Injection Attempt (CVE-2026-96889)
id: e471688b-38cc-4e95-a1b5-ec33f15a2c19
status: experimental
description: >
  Detects HTTP requests targeting Next.js Open Graph image generation
  endpoints (next/og ImageResponse) with SVG-related payloads. The
  next/og component on the Node.js runtime is vulnerable to
  CVE-2026-96889 even without dangerouslyAllowSVG being enabled,
  as it processes SVGs internally for OG image generation through
  the sharp/librsvg pipeline.
references:
  - https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw
  - https://nextjs.org/blog/nextjs-security-update-october-14-2026
  - https://www.netlify.com/changelog/2026-10-14-nextjs-react-security-vulnerabilities/
author: Actioner
date: 2026/10/16
tags:
  - attack.t1190
  - attack.t1203
  - cve.2026.96889
logsource:
  category: webserver
  service: access
detection:
  selection_og_endpoint:
    cs-uri-stem|contains:
      - '/api/og'
      - '/og-image'
      - '/opengraph-image'
  selection_svg_indicators:
    cs-uri-query|contains:
      - '.svg'
      - 'svg'
      - 'xmlns'
  condition: selection_og_endpoint and selection_svg_indicators
falsepositives:
  - Legitimate Open Graph image generation requests
  - Social media crawlers requesting OG images
level: medium
```

### Suricata/Snort Rules

Four network-level IDS rules targeting HTTP traffic patterns.

**File:** `nextjs_cve_2026_96889.rules`

| SID | Description | Confidence |
|---|---|---|
| 2026101601 | SVG requests to `/_next/image` endpoint | MEDIUM |
| 2026101602 | SVG payload with XInclude in request body | HIGH |
| 2026101603 | SVG with duplicate ENTITY declarations (exploit trigger) | HIGH |
| 2026101604 | Rapid POST with `Next-Action` header (DoS threshold) | LOW |

```
# Rule 1: SVG requests to /_next/image
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ACTIONER Next.js Image Optimization SVG Request - Potential CVE-2026-96889"; flow:established,to_server; http.uri; content:"/_next/image"; http.uri; content:".svg"; reference:cve,2026-96889; classtype:web-application-attack; sid:2026101601; rev:1;)

# Rule 2: SVG with XInclude in request body
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ACTIONER Next.js SVG XInclude Payload - Potential CVE-2026-96889 Exploit"; flow:established,to_server; http.request_body; content:"xi:include"; nocase; http.request_body; content:"<svg"; nocase; reference:cve,2026-96889; classtype:web-application-attack; sid:2026101602; rev:1;)

# Rule 3: Duplicate ENTITY declarations in SVG
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ACTIONER SVG Duplicate Entity Declaration - Potential CVE-2026-96889 Exploit"; flow:established,to_server; http.request_body; content:"<!ENTITY"; content:"<!ENTITY"; distance:1; http.request_body; content:"<svg"; nocase; reference:cve,2026-96889; classtype:web-application-attack; sid:2026101603; rev:1;)

# Rule 4: Server Actions DoS threshold
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ACTIONER Next.js Server Actions Rapid POST - Potential DoS"; flow:established,to_server; http.method; content:"POST"; http.header; content:"Next-Action"; threshold:type both, track by_src, count 50, seconds 10; classtype:attempted-dos; sid:2026101604; rev:1;)
```

---

## Non-Detectable Vulnerability: `use cache` RCE (GHSA-673q-mjm6-r5xr)

The `use cache` RCE in the React Flight protocol **cannot currently be detected with network-layer signatures**. The exploitation mechanism has not been publicly documented in sufficient detail to construct request-pattern-based detection rules. Detection for this flaw should rely on:

1. **Version-based inventory scanning** — Identify Next.js 16.0.0-16.4.0 deployments
2. **Dependency auditing** — Check `react-server-dom-*` package versions (19.0.0-19.3.0 are affected)
3. **Configuration auditing** — Identify applications with `cacheComponents: true` in `next.config.js`

---

## Remediation

### Immediate Actions

1. **Upgrade Next.js** to 16.4.1 or 15.5.28
2. **Verify sharp version** — Run `npm ls sharp` and confirm >= 0.35.5
3. **Verify librsvg version** — On glibc Linux: `dpkg -l librsvg2-2` or `rpm -q librsvg2` (need >= 2.63.2)
4. **Audit `dangerouslyAllowSVG`** — Disable if not strictly required
5. **Check deploy previews** — Delete publicly accessible branch/preview deploys running older versions

### Detection Deployment Priority

1. Deploy SVG XInclude detection (Rule 2 / SID 2026101602) — highest confidence, most specific to the exploit
2. Deploy `/_next/image` SVG monitoring (Rule 1 / SID 2026101601) — broad coverage of the primary attack surface
3. Deploy Server Actions DoS threshold (Rule 4 / SID 2026101604) — tune threshold per environment
4. Deploy OG image endpoint monitoring (Rule 4 Sigma) — adjust endpoint paths per application

---

## Related Vulnerabilities (Distinct)

These are separate from the October 14 patch but involve the same attack surface:

- **React2Shell (CVE-2025-55182 / CVE-2025-66478)** — December 2025 RSC Flight deserialization RCE (CVSS 10.0), exploited at scale. Distinct root cause from the `use cache` flaw.
- **CVE-2026-94545** — Satori/next/og SVG injection RCE (CVSS 9.5), fixed in 16.3.6. Distinct from the librsvg flaw.
- **CVE-2026-64641** — Server Actions CPU exhaustion, fixed in 15.5.21 and 16.2.11. May share root cause with GHSA-p3m5-59mp-jv5r.

---

## Sources

- [Next.js Security Update for Upstream Vulnerabilities (Vercel Blog)](https://nextjs.org/blog/nextjs-security-update-october-14-2026)
- [GHSA-673q-mjm6-r5xr: use cache RCE Advisory (GitHub)](https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr)
- [GHSA-2464-fhr4-w9xw: Image Optimization RCE Advisory (GitHub)](https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw)
- [GHSA-p3m5-59mp-jv5r: Server Actions DoS Advisory (GitHub)](https://github.com/vercel/next.js/security/advisories/GHSA-p3m5-59mp-jv5r)
- [GHSA-xqc2-xf4c-x3h3: React RSC RCE Advisory (GitHub)](https://github.com/react/react/security/advisories/GHSA-xqc2-xf4c-x3h3)
- [CVE-2026-96889 (Red Hat)](https://access.redhat.com/security/cve/cve-2026-96889)
- [Next.js Ships Out-of-Band Patch for Two Critical RCE Flaws (The Hacker News)](https://thehackernews.com/2026/10/nextjs-ships-out-of-band-patch-for-two.html)
- [Next.js & React Security Release Oct 2026 (Netlify)](https://www.netlify.com/changelog/2026-10-14-nextjs-react-security-vulnerabilities/)
- [Next.js Critical RCE Vulnerabilities: CVE-2026-96889 (The CyberSec Guru)](https://thecybersecguru.com/exploits/nextjs-critical-rce-vulnerabilities-cve-2026-96889/)
- [RCE in React Server Components (Ox Security)](https://www.ox.security/blog/rce-in-react-server-components/)
- [GHSA-wq5f-xc86-pv6w: sharp SVG Advisory (GitHub)](https://github.com/advisories/GHSA-wq5f-xc86-pv6w)
- [Next.js patches two unauthenticated RCEs (Azeem Hassni)](https://azeemhassni.com/blog/wire-nextjs-october-14-rce-patches/)
- [HOL: CVE-2026-96889 Next.js October 2026 Security Update](https://hol.org/blog/cve-2026-96889-nextjs-october-2026-security-update-rce)
