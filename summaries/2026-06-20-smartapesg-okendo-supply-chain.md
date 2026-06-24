# Technical Analysis Report: SmartApeSG Okendo Reviews Supply Chain Attack (2026-06-20)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-20
Version: 1.1 (REVISED)

## Executive Summary

On May 14, 2026, Zscaler ThreatLabz identified a supply chain attack in which the threat actor SmartApeSG injected malicious JavaScript into the legitimate Okendo Reviews widget, a customer review platform embedded by over 18,000 e-commerce brands. The compromised script -- served from `cdn-static[.]okendo[.]io` -- deployed an obfuscated loader that used localStorage tracking, User-Agent filtering (excluding mobile devices), and XOR-based deobfuscation to reconstruct next-stage C2 URLs. Victims were redirected to fake CAPTCHA and ClickFix-style social engineering lures that delivered remote access trojans (NetSupport RAT, Remcos RAT, Sectop RAT) and the StealC information stealer. Zscaler recorded nearly 15,000 blocks tied to SmartApeSG on the day of discovery alone. Impacted websites ranged from mid-sized stores to major U.S. retail brands receiving up to 7 million monthly visits. Okendo confirmed awareness and restored the widget to a clean state.

SmartApeSG (also overlapping with GrayCharlie per Recorded Future) has been active since mid-2023, primarily compromising WordPress sites and injecting externally hosted JavaScript to deliver fake browser update pages. This incident represents an escalation to third-party widget supply chain compromise, broadening the attack surface beyond individually compromised sites.

## Background: Okendo Reviews Widget

Okendo is a customer review and user-generated content platform used by over 18,000 e-commerce brands. The Reviews widget is a third-party JavaScript component embedded on storefront homepages, product pages, and review submission pages. Brands load the widget from Okendo's CDN (`cdn-static[.]okendo[.]io`), meaning a single compromise of the widget script could propagate malicious code across thousands of high-traffic e-commerce sites simultaneously. This architecture makes it an attractive supply chain target: the attacker needs to compromise only one upstream asset to reach a massive downstream audience.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Mid-2023 | SmartApeSG threat actor first observed in fake browser update campaigns |
| 2025-03-26 | Earlier SmartApeSG campaign documented by Malware Traffic Analysis delivering NetSupport RAT and StealC via fake browser updates on compromised sites |
| 2026-05-14 | Zscaler ThreatLabz detects anomalous SmartApeSG activity surge; identifies malicious JavaScript embedded in Okendo Reviews widget |
| 2026-05-14 | Zscaler platform records ~15,000 blocks tied to SmartApeSG in a single day |
| 2026-05-14 (est.) | Zscaler reports incident to Okendo |
| 2026-05-14+ | Okendo confirms awareness and restores widget script to clean state |
| 2026-06-19 | Public disclosure by Zscaler ThreatLabz |

## Root Cause: Third-Party Widget Supply Chain Compromise (T1195.002)

The attacker compromised the Okendo Reviews widget JavaScript served from `cdn-static[.]okendo[.]io/reviews-widget-plus/js/okendo-reviews[.]js`. The exact method of initial compromise of Okendo's CDN infrastructure has not been publicly disclosed. Because thousands of e-commerce sites include this script via a `<script>` tag pointing to Okendo's CDN, the injected malicious code was automatically served to all visitors of those sites without requiring any action by the site operators.

## Technical Analysis of the Malicious Payload

### 1. Stage 1 -- Injected JavaScript Loader (Okendo Widget)

The malicious code was embedded within the legitimate Okendo Reviews widget script at `cdn-static[.]okendo[.]io/reviews-widget-plus/js/okendo-reviews[.]js`. The loader performed several environment and execution-control checks before activating:

**localStorage Tracking:** The script used `localStorage['getItem']()` and `localStorage['setItem']()` with a tracking key to suppress repeated execution on the same browser, ensuring each victim was targeted only once:

```javascript
function _0x32dfc8() {
  const _0x490d08 = localStorage['getItem'](_0x4a5293);
  if (!_0x490d08) {
    localStorage['setItem'](_0x4a5293, Date['now']()[_0x26256c(0xde)]());
    return ![];
  }
}
```

**User-Agent Filtering:** Mobile devices were explicitly excluded, focusing the attack on desktop environments where the ClickFix social engineering lure is more effective:

```javascript
function _0x4e7869() {
  return /Android|iPhone/i ['test'](navigator['userAgent']);
}
```

**XOR-Based URL Reconstruction:** The loader split the next-stage URL into hex-encoded fragments and applied XOR-based decoding at runtime. The fragments were:

`['1f044640', '044a1d1f', '16005b1e', '0019484a', '141f5f1f', '141c5359', '1a031d43', '141f4255', '121d531e', '0718420f']`

This approach prevented the C2 URL from appearing in cleartext in the script, defeating basic signature-based detection. After deobfuscation, the loader dynamically injected a script element to retrieve the next stage.

**Randomized Token Generation:** The loader generated a random 8-character token appended to the retrieval URL as a query parameter, making each request unique.

### 2. Stage 2 -- ClickFix Social Engineering and Payload Staging

Upon successful loader execution, the victim was redirected to one of the SmartApeSG infrastructure domains, which presented either:

- A **fake CAPTCHA / verification prompt** (hosted on domains like `fresicrto[.]top`) designed to lure the victim into interacting, or
- A **fake browser update page** (on domains like `layardrama21[.]top`) mimicking Chrome, Edge, or Firefox update prompts.

The ClickFix lure instructed the victim to open the Windows Run dialog (Win+R) and paste a command, which executed an HTA dropper:

- **HTA Dropper:** Downloaded from `hxxps://urotypos[.]com/cd/temp` and saved to `C:\Users\<username>\AppData\Local\post.hta` (SHA256: `212d8007a7ce374d38949cf54d80133bd69338131670282008940f1995d7a720`, 47,714 bytes)
- The HTA used `mshta.exe` (T1218.005) to execute, subsequently invoking PowerShell or COMSPEC to download additional payloads.

### 3. Stage 3 -- Multi-RAT Deployment

A single infection chain delivered up to four distinct malware families in sequence, using DLL side-loading across multiple payloads:

**Remcos RAT** (deployed first, ~17:11 UTC):
- Retrieved from: `hxxps://urotypos[.]com/ls/production`
- SHA256: `a6a748c0606fb9600fdf04763523b7da20b382b054b875fdd1ef1c36fc16079a` (85,328,653 bytes)
- C2: `95.142.45[.]231:443`

**NetSupport RAT** (deployed ~4 min later, ~17:16 UTC):
- Package: `UpdateInstaller.zip`
- SHA256: `6e26ff49387088178319e116700b123d27216d98ba3ae1ce492544cb9acd38f0` (9,171,647 bytes)
- Executable: `client32.exe` with supporting files (`client32.ini`)
- C2: `185.163.47[.]220:443`
- Persistence: Registry Run key (`HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`) pointing to `client32.exe`

**StealC** (deployed ~1 hour later, ~18:18 UTC):
- SHA256: `a7b9be1211c6de76bab31dbcd3a1c99861cf18e3230ea9f634e07d22c179d1ca` (6,178,471 bytes)
- Saved to: `C:\Users\Public\Music\finalmesh.zip`
- C2: `89.46.38[.]100:80`
- Exfiltration endpoint: `193.239.237[.]40` (with per-host hex identifiers like `/52a50518b868057e.php`)

**Sectop RAT (ArechClient2)** (deployed ~1.3 hours later, ~19:36 UTC):
- SHA256: `c90435370728d48cba1c00d92cc3bf99e85f01aa52ecd6c6df2e8137db964796` (6,908,049 bytes)
- Saved to: `C:\ProgramData\drag2pdf.zip`
- C2: `195.85.115[.]11:9000`

### 4. C2 Infrastructure

SmartApeSG infrastructure is primarily hosted on MivoCloud and HZ Hosting Ltd (per Recorded Future/Insikt Group). Key C2 nodes:

| IP Address | Port | Role |
|------------|------|------|
| 95.142.45[.]231 | 443 | Remcos RAT C2 |
| 185.163.47[.]220 | 443 | NetSupport RAT C2 |
| 89.46.38[.]100 | 80 | StealC C2 |
| 195.85.115[.]11 | 9000 | Sectop RAT C2 |
| 193.239.237[.]40 | 80 | StealC exfiltration |
| 194.180.191[.]168 | 443 | NetSupport C2 (prior campaign) |

Staging domains:
- `api[.]wigetticks[.]com` -- Next-stage script retrieval (`/logout/private-response[.]php?8D1V4th3`)
- `api[.]wizzleticks[.]com` -- Next-stage script retrieval (`/claims/scope-schema[.]php?4ManBBdA`)
- `urotypos[.]com` -- Payload staging (`/cd/temp`, `/ls/production`)
- `fresicrto[.]top` -- Fake CAPTCHA page hosting
- `layardrama21[.]top` -- Fake browser update page hosting

### 5. Anti-Forensics / Evasion Techniques

- **Obfuscated variable names:** All JavaScript functions and variables use hex-encoded obfuscated identifiers (e.g., `_0x32dfc8`, `_0x4a5293`)
- **XOR-encoded infrastructure:** C2 URLs are never present in cleartext; reconstructed at runtime from hex fragments
- **Single-execution guard:** localStorage check prevents re-triggering on repeat visits
- **Mobile exclusion:** User-Agent filtering ensures only desktop targets proceed (where ClickFix is effective)
- **DLL side-loading:** Legitimate executables used to load malicious DLLs, evading application allowlisting
- **File deletion (T1070.004) and persistence clearing (T1070.009):** Observed in post-exploitation cleanup

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Okendo Reviews Widget | Compromised (May 14, 2026) | Malicious JS loader injected into `okendo-reviews.js` |

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|-----------------|---------------|-------------|
| Windows | `C:\Users\<user>\AppData\Local\post.hta` | `212d8007a7ce374d38949cf54d80133bd69338131670282008940f1995d7a720` | HTA dropper (47,714 bytes) |
| Windows | Remcos RAT package | `a6a748c0606fb9600fdf04763523b7da20b382b054b875fdd1ef1c36fc16079a` | Remcos RAT (85,328,653 bytes) |
| Windows | `UpdateInstaller.zip` | `6e26ff49387088178319e116700b123d27216d98ba3ae1ce492544cb9acd38f0` | NetSupport RAT package (9,171,647 bytes) |
| Windows | `C:\Users\Public\Music\finalmesh.zip` | `a7b9be1211c6de76bab31dbcd3a1c99861cf18e3230ea9f634e07d22c179d1ca` | StealC package (6,178,471 bytes) |
| Windows | `C:\ProgramData\drag2pdf.zip` | `c90435370728d48cba1c00d92cc3bf99e85f01aa52ecd6c6df2e8137db964796` | Sectop RAT package (6,908,049 bytes) |
| Windows | `client32.exe` | -- | NetSupport RAT executable |
| Windows | MTA fake browser update JS | `68c6411cc9afa68047641932530cf7201f17029167d4811375f1458cae32c7bd` | Prior campaign JS dropper (831,080 bytes) |
| Windows | `mfpmp.exe` (legit, sideloaded) | `ff7e8ccc41bc3a506103bdd719a19318bf711351ac0e61e1f1cf00f5f02251d5` | Legitimate EXE used for DLL sideloading |
| Windows | `rtworkq.dll` (malicious) | `2bc17933b9dd18627610a509736f8cf6c149338be5f6bd3d475ea22d0d914ae3` | Malicious DLL sideloaded by mfpmp.exe |
| Windows | `C:\Users\Public\misk.zip` | `45085f479b048dd0ef48bef5b8c78618113bc19bde6349f61d184cdf4331bff0` | Prior campaign StealC delivery archive |
| Windows | NetSupport RAT ZIP (prior campaign) | `4c048169e303dc3438e53e5abdec31b45b5184f05dc6d1bc39e18caa0e4a3f3e` | Prior campaign NetSupport package |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | cdn-static[.]okendo[.]io | Compromised widget CDN (legitimate, was serving malicious JS) |
| Domain | api[.]wigetticks[.]com | SmartApeSG next-stage C2 |
| Domain | api[.]wizzleticks[.]com | SmartApeSG next-stage C2 |
| Domain | fresicrto[.]top | Fake CAPTCHA page hosting |
| Domain | urotypos[.]com | Payload staging server |
| Domain | layardrama21[.]top | Fake browser update page hosting (prior campaign) |
| URL | hxxps://api[.]wigetticks[.]com/logout/private-response[.]php?8D1V4th3 | Next-stage script retrieval |
| URL | hxxps://api[.]wizzleticks[.]com/claims/scope-schema[.]php?4ManBBdA | Next-stage script retrieval |
| URL | hxxps://urotypos[.]com/cd/temp | HTA dropper staging |
| URL | hxxps://urotypos[.]com/ls/production | Remcos RAT staging |
| IP | 95.142.45[.]231:443 | Remcos RAT C2 |
| IP | 185.163.47[.]220:443 | NetSupport RAT C2 |
| IP | 89.46.38[.]100:80 | StealC C2 |
| IP | 195.85.115[.]11:9000 | Sectop RAT C2 |
| IP | 193.239.237[.]40 | StealC exfiltration |
| IP | 194.180.191[.]168:443 | NetSupport C2 (prior campaign) |
| Detection | JS.Injection.SmartApeSG | Zscaler threat classification |

### Behavioral

- `mshta.exe` executing HTA files from `AppData\Local` directory (T1218.005)
- Registry Run key persistence for `client32.exe` (T1547.001)
- ZIP archives dropped to `C:\Users\Public\Music\` and `C:\ProgramData\` (T1074.001)
- DLL side-loading using legitimate Windows executables (T1574.001)
- PowerShell or COMSPEC spawned from HTA execution context (T1059.001)
- Web page injecting `<script>` tags that perform localStorage checks and User-Agent filtering before loading external resources

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious JS injected into Okendo Reviews third-party widget served to 18,000+ brands |
| T1204.001 | User Execution: Malicious Link | Fake CAPTCHA and browser update prompts lure victims into clicking |
| T1204.002 | User Execution: Malicious File | ClickFix instructs victims to execute pasted commands |
| T1218.005 | System Binary Proxy Execution: Mshta | HTA dropper executed via mshta.exe from AppData\Local |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell used to download and extract payloads |
| T1574.001 | Hijack Execution Flow: DLL Side-Loading | Legitimate executables load malicious DLLs (mfpmp.exe + rtworkq.dll) |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | NetSupport RAT persists via HKCU Run key |
| T1027 | Obfuscated Files or Information | Variable obfuscation, XOR-encoded URL fragments in JS loader |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | XOR deobfuscation of C2 infrastructure at runtime |
| T1140 | Deobfuscate/Decode Files or Information | XOR decode of hex fragments to reconstruct URLs |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication over HTTP/HTTPS |
| T1105 | Ingress Tool Transfer | Multi-stage payload download from staging domains |
| T1074.001 | Data Staged: Local Data Staging | ZIP archives staged in Public\Music and ProgramData |
| T1070.004 | Indicator Removal: File Deletion | Post-exploitation cleanup of dropped files |
| T1070.009 | Indicator Removal: Clear Persistence | Removal of persistence artifacts after operation |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | User-Agent and localStorage checks to filter execution environment |

## Impact Assessment

**Breadth:** The compromised Okendo widget was embedded on sites used by 18,000+ brands. During the observation window, affected sites ranged from ~150,000 to ~7 million monthly visits per site. Zscaler recorded ~15,000 blocks on May 14 alone, suggesting tens of thousands of potential exposure events.

**Depth:** Successful infections resulted in deployment of up to four malware families (Remcos, NetSupport, StealC, Sectop RAT), providing attackers with full remote access, credential theft, and persistent backdoor capabilities. StealC specifically targets passwords, browser cookies, cryptocurrency wallets, and financial credentials.

**Stealth:** The XOR-encoded URL reconstruction, localStorage-based single-execution guard, and mobile exclusion filtering demonstrate a focus on evading both automated and manual detection. The supply chain vector means site operators had no visibility into the compromise -- the malicious code was served from a trusted third-party CDN.

## Detection & Remediation

### Immediate Detection

**Check for widget inclusion:**
```bash
# Search web server files for Okendo widget references
grep -r "cdn-static.okendo.io" /var/www/ --include="*.html" --include="*.php" --include="*.js"
grep -r "okendo-reviews.js" /var/www/ --include="*.html" --include="*.php" --include="*.js"
```

**Check DNS/proxy logs for C2 domains:**
```
# Splunk query
index=dns OR index=proxy (query="*wigetticks.com" OR query="*wizzleticks.com" OR query="*fresicrto.top" OR query="*urotypos.com" OR query="*layardrama21.top")
```

**Check endpoint logs for HTA dropper:**
```
# Splunk query for mshta abuse
index=sysmon EventCode=1 Image="*\\mshta.exe" CommandLine="*post.hta*"
```

**Check for known C2 IP connections:**
```
# Splunk query
index=firewall OR index=proxy dest_ip IN ("95.142.45.231","185.163.47.220","89.46.38.100","195.85.115.11","193.239.237.40","194.180.191.168")
```

### Remediation

1. **Verify Okendo widget integrity:** Confirm the current version of the Okendo widget loaded on your site matches the clean version. Contact Okendo support for hash verification.
2. **Block IOC domains and IPs:** Add all network IOCs to firewall/proxy blocklists.
3. **Scan endpoints:** Run IOC sweeps for the file hashes listed above. Check for `client32.exe` in registry Run keys, archives in `C:\Users\Public\Music\` and `C:\ProgramData\`, and `post.hta` in `AppData\Local`.
4. **Rotate credentials:** If any endpoint was compromised, rotate all passwords, API keys, and session tokens accessed from that machine. StealC specifically targets stored browser credentials and cryptocurrency wallets.
5. **Review CSP headers:** Implement or audit Content Security Policy headers to restrict which external scripts can execute on your pages.

### Long-Term Hardening

- **Subresource Integrity (SRI):** Add `integrity` attributes to all third-party `<script>` tags so browsers refuse to execute scripts whose content has been modified.
- **Content Security Policy (CSP):** Deploy strict CSP headers with explicit allowlists for script sources.
- **Third-party script monitoring:** Implement continuous monitoring of third-party script behavior (e.g., via tools like Feroot, Source Defense, or browser-based script change detection).
- **Vendor security assessments:** Require third-party widget providers to demonstrate supply chain security controls (code signing, access controls on CDN, incident response SLAs).

## Detection Rules

The rules below cover the SmartApeSG Okendo supply chain attack across network (Snort/Suricata), file (YARA), and endpoint (Sigma) detection surfaces. All IOC-based rules use real (non-defanged) indicator values; the network IOC rules are high-confidence but time-limited as infrastructure rotates. Behavioral rules detecting the mshta/HTA and registry persistence patterns are medium-confidence as they may match other ClickFix campaigns.

### Sigma: SmartApeSG DNS Query to C2 Domains

Detects DNS queries to known SmartApeSG C2 and staging domains used in the Okendo supply chain attack.

<!-- revision: v1.1 - Fixed endswith inconsistency: added leading dots to fresicrto.top, urotypos.com, layardrama21.top; added exact-match entries for bare domains. -->
<!-- audit: IOC-based rule matching 5 specific domains from Zscaler ThreatLabz and SANS ISC reports. High confidence for known infrastructure but domains may rotate. No FP expected for these specific domains. Validated: sigma check 0 errors, sigma convert splunk+log_scale successful. Tags: T1071.001 (web protocols), T1105 (ingress tool transfer). -->

**Compile:** sigma check + sigma convert (splunk, log_scale) -- all passed

```yaml
title: SmartApeSG Okendo Supply Chain - DNS Query to SmartApeSG C2 Domains
id: 8a3e7f1b-2c4d-4e5a-9b6f-1d0e8c7a3f2b
status: experimental
description: >
    Detects DNS queries to known SmartApeSG command-and-control and staging
    domains used in the Okendo Reviews supply chain attack to deliver
    fake browser updates and RAT payloads.
references:
    - https://www.zscaler.com/blogs/security-research/smartapesg-launches-okendo-reviews-supply-chain-attack
    - https://isc.sans.edu/diary/32826
author: Actioner
date: 2026-06-20
tags:
    - attack.t1071.001
    - attack.t1105
logsource:
    category: dns_query
detection:
    selection_sub:
        QueryName|endswith:
            - '.wigetticks.com'
            - '.wizzleticks.com'
            - '.fresicrto.top'
            - '.urotypos.com'
            - '.layardrama21.top'
    selection_exact:
        QueryName:
            - 'wigetticks.com'
            - 'wizzleticks.com'
            - 'fresicrto.top'
            - 'urotypos.com'
            - 'layardrama21.top'
    condition: 1 of selection_*
falsepositives:
    - Unlikely given the specificity of these domains
level: high
```

Status: compiled | Confidence: high (IOC-based)

---

### Sigma: SmartApeSG Mshta Execution of HTA Dropper

Detects mshta.exe executing `post.hta` from AppData\Local, matching the SmartApeSG ClickFix dropper delivery path.

<!-- audit: Behavioral rule matching specific file path post.hta in AppData\Local via mshta.exe. Medium confidence because the filename post.hta could theoretically appear in other ClickFix campaigns. Process_creation logsource requires Sysmon EID 1 or Windows 4688 with command line auditing. Tags: T1218.005 (mshta), T1204.002 (malicious file). Validated: sigma check 0 errors, sigma convert splunk+log_scale successful. -->

**Compile:** sigma check + sigma convert (splunk, log_scale) -- all passed

```yaml
title: SmartApeSG Okendo Supply Chain - Mshta Execution of HTA Dropper
id: 9b4f8e2c-3d5e-4f6b-ac7d-2e1f9d8b4a3c
status: experimental
description: >
    Detects mshta.exe executing an HTA file from the AppData\Local directory,
    consistent with the SmartApeSG ClickFix attack chain that drops post.hta
    to deliver RAT payloads.
references:
    - https://www.zscaler.com/blogs/security-research/smartapesg-launches-okendo-reviews-supply-chain-attack
    - https://isc.sans.edu/diary/32826
author: Actioner
date: 2026-06-20
tags:
    - attack.t1218.005
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\mshta.exe'
        CommandLine|contains: '\AppData\Local\post.hta'
    condition: selection
falsepositives:
    - Legitimate HTA files named post.hta in AppData (very unlikely)
level: high
```

Status: compiled | Confidence: medium (behavioral/path-specific)

---

### Sigma: SmartApeSG NetSupport RAT Registry Persistence

Detects registry Run key modification referencing client32.exe, the NetSupport RAT executable used in SmartApeSG campaigns.

<!-- revision: v1.1 - Downgraded level from high to medium; legitimate NetSupport Manager is a known FP source, matching stated medium confidence. -->
<!-- audit: Behavioral rule matching registry_set events where Run key value contains client32.exe. Medium confidence due to legitimate NetSupport Manager enterprise deployments. Requires Sysmon EID 13. Tags: T1547.001 (registry run keys). Validated: sigma check 0 errors, sigma convert splunk+log_scale successful. -->

**Compile:** sigma check + sigma convert (splunk, log_scale) -- all passed

```yaml
title: SmartApeSG Okendo Supply Chain - NetSupport RAT Registry Persistence
id: ac5d9f3e-4e6f-5a7c-bd8e-3f2a0e9c5b4d
status: experimental
description: >
    Detects registry Run key modification to establish persistence for
    NetSupport RAT client32.exe, a known payload in SmartApeSG campaigns
    including the Okendo supply chain attack.
references:
    - https://www.esentire.com/blog/smartapesg-delivering-netsupport-rat
    - https://www.zscaler.com/blogs/security-research/smartapesg-launches-okendo-reviews-supply-chain-attack
author: Actioner
date: 2026-06-20
tags:
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        Details|contains: 'client32.exe'
    condition: selection
falsepositives:
    - Legitimate NetSupport Manager deployments in enterprise environments
level: medium
```

Status: compiled | Confidence: medium (behavioral; legitimate NetSupport Manager is a known FP source)

---

### Sigma: SmartApeSG Archive Staging in Public/ProgramData -- CUT

<!-- revision: v1.1 - Rule removed during review. ProgramData + .zip matching was too broad, producing excessive false positives from legitimate software installers. The behavioral pattern (ZIP archive drops to Public\Music or ProgramData) is covered implicitly by the C2 IP and DNS domain rules. -->

---

### Sigma: SmartApeSG Network Connection to Known C2 IPs

Detects outbound connections to SmartApeSG C2 IP addresses used for Remcos, NetSupport, StealC, and Sectop RAT command and control.

<!-- revision: v1.1 - Downgraded level from critical to high; IOC-based IP rules are time-limited as IPs get reassigned, so critical is overstated. -->
<!-- audit: IOC-based rule matching 6 specific C2 IPs from SANS ISC and MTA sources. High confidence but time-limited as IPs may be reassigned. Requires Sysmon EID 3 or equivalent. Tags: T1071.001 (web protocols). Validated: sigma check 0 errors, sigma convert splunk+log_scale successful. -->

**Compile:** sigma check + sigma convert (splunk, log_scale) -- all passed

```yaml
title: SmartApeSG Okendo Supply Chain - Network Connection to Known C2 IPs
id: ce7fb15a-6a8b-7c9e-dfa0-5b4c2abc7d6f
status: experimental
description: >
    Detects outbound network connections to IP addresses associated with
    SmartApeSG C2 infrastructure used for Remcos RAT, NetSupport RAT,
    StealC, and Sectop RAT command and control.
references:
    - https://isc.sans.edu/diary/32826
    - https://www.zscaler.com/blogs/security-research/smartapesg-launches-okendo-reviews-supply-chain-attack
author: Actioner
date: 2026-06-20
tags:
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        Initiated: 'true'
        DestinationIp:
            - '95.142.45.231'
            - '185.163.47.220'
            - '89.46.38.100'
            - '195.85.115.11'
            - '193.239.237.40'
            - '194.180.191.168'
    condition: selection
falsepositives:
    - Unlikely given specific C2 IP indicators; however IPs may be reassigned over time
level: high
```

Status: compiled | Confidence: high (IOC-based, time-limited)

---

### YARA: SmartApeSG Okendo JS Injection Loader

Detects the obfuscated JavaScript loader injected into the Okendo widget, matching XOR hex fragment patterns, localStorage tracking, and C2 domain strings.

<!-- audit: Three detection branches: (1) localStorage+UA filtering pattern, (2) XOR hex fragment cluster (3 of 6 fragments), (3) C2 domain + PHP path combo. Medium confidence because individual strings may appear in benign contexts; the combination reduces FPs. File size cap 5MB appropriate for JS. Validated: yarac exit 0. -->

**Compile:** yarac -- exit 0

```yara
rule SmartApeSG_Okendo_JS_Injection_Loader
{
    meta:
        description = "Detects the SmartApeSG JavaScript injection loader ..."
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://www.zscaler.com/blogs/security-research/..."
        severity = "high"
    strings:
        $ls1 = "localStorage['getItem']" ascii
        $ls2 = "localStorage['setItem']" ascii
        $ua = "/Android|iPhone/i" ascii
        $ua2 = "navigator['userAgent']" ascii
        $xor1 = "1f044640" ascii
        ...
    condition:
        filesize < 5MB and (
            (2 of ($ls*) and 1 of ($ua*)) or
            (3 of ($xor*)) or
            (1 of ($domain*) and 1 of ($path*))
        )
}
```

Status: compiled | Confidence: medium (pattern-based; XOR fragments are distinctive but loader variants may differ)

---

### YARA: SmartApeSG HTA Dropper

Detects the HTA dropper payload used in the SmartApeSG ClickFix chain, matching staging domain and path artifacts.

<!-- revision: v1.1 - Tightened branch 3 of condition to require $url1 (urotypos.com); previously any HTA with PowerShell + ProgramData would match, which is too broad. -->
<!-- audit: Matches HTA structure tags + urotypos.com staging domain, or domain + PowerShell cmdlets, or HTA + PS + staging paths + urotypos.com. Hash pinned: 212d8007... Medium confidence; different campaigns may use different HTA structures. Validated: yarac exit 0. -->

**Compile:** yarac -- exit 0

Status: compiled | Confidence: medium (behavioral + partial IOC)

---

### YARA: SmartApeSG Fake Browser Update JS

Detects SmartApeSG fake browser update JavaScript dropper files targeting NetSupport RAT delivery.

<!-- audit: Matches filename patterns (Update_browser, UpdateInstaller) combined with NetSupport artifacts (client32.exe, client32.ini, rtrs.zip). Medium confidence; NetSupport artifacts are distinctive but not unique to SmartApeSG. Validated: yarac exit 0. -->

**Compile:** yarac -- exit 0

Status: compiled | Confidence: medium (behavioral)

---

### Snort: SmartApeSG C2 Domain and IP Rules (10 rules)

Ten Snort 2.9 rules detecting HTTP requests to SmartApeSG C2 domains (wigetticks, wizzleticks, urotypos, fresicrto) and TCP connections to known C2 IP:port combinations.

<!-- audit: SID range 2100201-2100210. Domain rules match on content in HTTP stream (Host header + URI path). IP rules match on destination IP with specific ports. All use flow:established,to_server. High confidence for IOC rules but time-limited. Validated: snort -c config -T "Snort successfully validated the configuration!". -->

**Compile:** snort -T -- Snort successfully validated the configuration!

Status: compiled | Confidence: high (IOC-based, 4 domain rules + 6 IP rules)

---

### Suricata: SmartApeSG DNS, HTTP, and IP Rules (9 rules)

Nine Suricata 7.x rules using dns.query and http.host/http.uri sticky buffers for SmartApeSG domain detection, plus a consolidated TCP rule matching all six known C2 IPs.

<!-- audit: SID range 2100301-2100309. DNS rules use dns.query buffer with nocase. HTTP rules use http.host + http.uri dot-notation buffers. IP rule uses bracket notation for IP group. All use appropriate flow directives. Validated: suricata -T -S "Configuration provided was successfully loaded. Exiting." -->

**Compile:** suricata -T -- Configuration provided was successfully loaded. Exiting.

Status: compiled | Confidence: high (IOC-based, 5 DNS rules + 3 HTTP rules + 1 IP rule)

## Lessons Learned

1. **Third-party widget supply chains remain a critical blind spot.** Unlike dependency-level supply chain attacks (e.g., npm packages), widget-level compromises affect runtime execution on production pages. Subresource Integrity (SRI) attributes on `<script>` tags would have prevented execution of the modified widget, but SRI adoption for dynamic third-party widgets remains low because vendors frequently update their scripts, breaking fixed hashes.

2. **ClickFix social engineering continues to evolve.** The SmartApeSG campaign combines a supply chain vector (mass exposure) with ClickFix-style user interaction requirements (high-value targeting). The mobile exclusion filter shows increasing sophistication in victim selection -- attackers know the Run dialog technique only works on desktop Windows.

3. **Multi-RAT deployment increases attacker resilience.** Deploying four distinct malware families (Remcos, NetSupport, StealC, Sectop) in a single infection chain provides redundancy: if defenders detect and remove one, others may persist. This also suggests a possible access broker model where different tools serve different operational needs.

## Sources

- [Zscaler ThreatLabz - SmartApeSG Launches Okendo Reviews Supply Chain Attack](https://www.zscaler.com/blogs/security-research/smartapesg-launches-okendo-reviews-supply-chain-attack) -- primary technical analysis and IOCs for the Okendo widget compromise
- [SANS ISC Diary 32826 - SmartApeSG Campaign](https://isc.sans.edu/diary/32826) -- detailed infection chain with file hashes, C2 IPs, and timeline for Remcos/NetSupport/StealC/Sectop deployment
- [eSentire - SmartApeSG Delivering NetSupport RAT](https://www.esentire.com/blog/smartapesg-delivering-netsupport-rat) -- earlier SmartApeSG campaign analysis with NetSupport RAT delivery details and registry persistence
- [Malware Traffic Analysis - 2025-03-26 SmartApeSG Traffic](https://www.malware-traffic-analysis.net/2025/03/26/index.html) -- network traffic captures and file hashes from prior SmartApeSG campaign
- [SOC Prime - SmartApeSG Delivers Remcos, StealC, and Sectop RAT](https://socprime.com/active-threats/smartapesg-delivers-remcos/) -- MITRE ATT&CK mapping and detection focus areas
- [Recorded Future - GrayCharlie Hijacks Law Firm Sites](https://www.recordedfuture.com/research/graycharlie-hijacks-law-firm-sites-suspected-supply-chain-attack) -- GrayCharlie/SmartApeSG overlap analysis and infrastructure attribution
- [CyberSecurity News - Hackers Abuse Third-Party Okendo Reviews Script](https://cybersecuritynews.com/hackers-abuse-third-party-okendo-reviews-script/) -- secondary reporting on the Okendo incident
- [GBHackers - SmartApeSG Hackers Abuse Okendo Reviews Widget](https://gbhackers.com/smartapesg-hackers-abuse-okendo-reviews/) -- secondary reporting with additional context

---
*Report generated by Actioner*
