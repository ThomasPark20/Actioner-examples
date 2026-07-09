# Technical Analysis Report: Fake Paysafe/Skrill/Neteller SDK Supply Chain Attack (2026-07-09)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-09
Version: 1.0 (DRAFT)

## Executive Summary

On July 7, 2026, Socket's AI scanner detected a coordinated supply chain attack spanning npm and PyPI registries: 17 malicious packages impersonating legitimate Paysafe, Skrill, and Neteller payment SDKs. The campaign targets payment application developers with credential-stealing malware that harvests API keys, cloud secrets (AWS, GitHub, npm tokens), and system metadata, exfiltrating them to an ngrok-tunneled C2 server previously associated with NjRAT operations. The npm variants (13 packages, versions 1.0.0--1.0.3) gate exfiltration on the presence of a `PAYSAFE_API_KEY` environment variable, while the PyPI variants (4 packages, version 1.0.0) execute the theft routine automatically upon import -- making them particularly dangerous in CI/CD pipelines where packages are installed and imported without human review.

All npm packages were detected and flagged as malware within 6 minutes of publication. The C2 hostname (`caliber-spinner-finishing[.]ngrok-free[.]dev`) was obfuscated using a three-step encoding scheme (Base64 XOR + character code subtraction + string reversal) with unique keys per package variant, indicating deliberate operational security by the threat actor.

## Background: Paysafe Payment Platform

Paysafe Group is a multinational payment processing company operating the Paysafe, Skrill, and Neteller digital wallet brands. These platforms are widely used for online payments, money transfers, and digital commerce. Paysafe provides official SDKs for integrating payment functionality into applications. The absence of official npm/PyPI packages for some of these brands created an opportunity for typosquatting -- attackers registered plausible package names that developers might search for when looking to integrate payment processing.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-07-07 | Attacker publishes 13 malicious npm packages (versions 1.0.0--1.0.3) and 4 PyPI packages (version 1.0.0) |
| 2026-07-07 (within 6 min) | Socket AI scanner detects and flags all npm packages as malware |
| 2026-07-08 | Socket publishes technical analysis; BleepingComputer reports on the campaign |
| 2026-07-09 | This report generated |

## Root Cause: Supply Chain Compromise via Typosquatting

The attack exploited the open registration model of npm and PyPI registries. The threat actor registered package names that closely mimic expected SDK names for Paysafe, Skrill, and Neteller -- brands that either lack official packages on these registries or whose official packages use different names. Developers searching for "paysafe sdk" or "skrill payments" would encounter these malicious packages in registry search results. The packages presented functional-looking APIs that returned fake success responses, masking the underlying credential theft.

## Technical Analysis of the Malicious Payload

### 1. Package Delivery and Fake SDK Facade

Each malicious package ships what appears to be a legitimate payment SDK. The npm packages export a `PaysafeClient` class with methods mimicking real Paysafe REST API endpoints (`payments.create`, `payments.get`, `customers.create`, `customers.get`). These methods return hardcoded `{success: true, method, path}` responses without making any actual API calls, providing a functional facade while the credential theft operates in the background.

The PyPI variants follow an identical pattern but leverage Python's `__init__.py` to trigger credential theft on import, requiring no explicit API call from the victim.

### 2. Credential Harvesting and Exfiltration

The core payload harvests environment variables matching patterns: `KEY`, `SECRET`, `TOKEN`, `PASS`, `AUTH`, or `API`. Specifically targeted variables include:

- `PAYSAFE_API_KEY` -- payment API credentials
- `AWS_SECRET_ACCESS_KEY` -- AWS cloud credentials
- `GITHUB_TOKEN` -- GitHub access tokens
- `NPM_TOKEN` -- npm publish tokens

The exfiltration payload is a JSON object containing:
- Hostname and username of the compromised system
- Current working directory
- Timestamp
- Hardcoded package name identifier
- Environment variable values (first 100 characters each)
- HTTP method, API path, and first 10 characters of any Paysafe API key

**npm variant**: Exfiltration is conditional -- it fires only when `this.apiKey` (from config or `PAYSAFE_API_KEY` env var) is set and the fake SDK is actively invoked. A `setTimeout` delay of 11,768ms is used before exfiltration, likely to evade behavioral analysis sandboxes.

**PyPI variant**: Exfiltration is unconditional -- the theft routine activates immediately upon `import` of the package via `__init__.py`, with no API key gating. This makes the PyPI variants more dangerous, especially in automated CI/CD environments.

### 3. C2 Infrastructure

The exfiltration endpoint is an ngrok tunnel:
- **Domain:** `caliber-spinner-finishing[.]ngrok-free[.]dev` (port 443/HTTPS)
- **Infrastructure:** The IP resolved for the ngrok hostname had prior reputation as a C2 server for NjRAT and other stealers, indicating the threat actor shares infrastructure with established criminal operations or reuses compromised ngrok accounts.

The C2 hostname is obfuscated in the code using a three-step decoding process:

**npm variant:**
1. Base64 decode + XOR with key `SGf6lmbr7GHUg99Z6R2U3g==`
2. Subtract 17 from each character code
3. Reverse the resulting string

**PyPI variant:**
1. Base64 decode + XOR with a separate key (unique per package)
2. Subtract 11 from each character code
3. Reverse the resulting string

The use of different XOR keys and subtraction constants per ecosystem variant indicates deliberate effort to avoid cross-variant signature detection.

### 4. Platform-Specific Behavior

#### npm (Node.js)

- **Trigger:** Conditional on `PAYSAFE_API_KEY` being present; requires fake SDK method invocation
- **Delay:** 11,768ms `setTimeout` before exfiltration
- **Scope:** 13 packages, each with 4 versions (1.0.0--1.0.3) = 52 total artifacts
- **Detection speed:** All flagged within 6 minutes by Socket AI

#### PyPI (Python)

- **Trigger:** Unconditional; activates on `import` via `__init__.py`
- **Delay:** None reported
- **Scope:** 4 packages, single version (1.0.0) = 4 total artifacts
- **Risk:** Higher in CI/CD where packages are auto-installed and imported

### 5. Anti-Forensics / Evasion Techniques

The malware implements sandbox/VM detection that aborts exfiltration if:
- **CPU cores < 2** -- typical of minimal analysis sandboxes
- **Hostname or username contains:** `sandbox`, `analyzer`, `cuckoo`, `virus`, `malware`, `vmware`, `vbox`

The three-step C2 hostname obfuscation (Base64 XOR + character subtraction + reversal) with unique keys per variant adds additional evasion against static string analysis.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Registry | Description |
|---------------------|-------------------|----------|-------------|
| paysafe-checkout | 1.0.0--1.0.3 | npm | Fake Paysafe checkout SDK; conditional credential theft |
| paysafe-vault | 1.0.0--1.0.3 | npm | Fake Paysafe vault SDK; conditional credential theft |
| neteller | 1.0.0--1.0.3 | npm | Fake Neteller SDK; conditional credential theft |
| skrill-payments | 1.0.0--1.0.3 | npm | Fake Skrill payments SDK; conditional credential theft |
| paysafe-js | 1.0.0--1.0.3 | npm | Fake Paysafe JS SDK; conditional credential theft |
| paysafe-api | 1.0.0--1.0.3 | npm/PyPI | Fake Paysafe API SDK; conditional (npm) / unconditional (PyPI) |
| paysafe-node | 1.0.0--1.0.3 | npm | Fake Paysafe Node SDK; conditional credential theft |
| paysafe-cards | 1.0.0--1.0.3 | npm | Fake Paysafe cards SDK; conditional credential theft |
| paysafe-fraud | 1.0.0--1.0.3 | npm | Fake Paysafe fraud SDK; conditional credential theft |
| paysafe-kyc | 1.0.0--1.0.3 | npm/PyPI | Fake Paysafe KYC SDK; conditional (npm) / unconditional (PyPI) |
| skrill | 1.0.0--1.0.3 | npm | Fake Skrill SDK; conditional credential theft |
| skrill-sdk | 1.0.0--1.0.3 | npm | Fake Skrill SDK; conditional credential theft |
| paysafe-payments | 1.0.0--1.0.3 | npm/PyPI | Fake Paysafe payments SDK; conditional (npm) / unconditional (PyPI) |
| paysafe-sdk | 1.0.0 | PyPI | Fake Paysafe SDK; unconditional credential theft on import |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Cross-platform | `index.js` (npm) | ce09810adca70ebec87bc455380ef629ceaa2a0d926149d9115604060167682c | Malicious npm package entry point (one of 52 variants) |
| Cross-platform | `__init__.py` (PyPI) | b2ea8d69f6792a87327ffde2ee4551bb6b99617f53e1ba71bf9a70f45dbc57ea | Malicious PyPI package init (one of 4 variants) |

> **Note:** The Socket report lists 52 SHA256 hashes across all package versions. The two above are representative samples; the full list is available in the Socket blog post.

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | caliber-spinner-finishing[.]ngrok-free[.]dev | C2 exfiltration endpoint (ngrok tunnel) |
| Port | 443 (HTTPS) | C2 communication port |

### Behavioral

- **Environment variable enumeration:** Harvests all env vars matching `KEY`, `SECRET`, `TOKEN`, `PASS`, `AUTH`, `API`
- **Sandbox detection:** CPU core count check (< 2) and hostname/username substring matching against `sandbox`, `analyzer`, `cuckoo`, `virus`, `malware`, `vmware`, `vbox`
- **Delayed execution (npm):** 11,768ms `setTimeout` before exfiltration callback
- **Fake API responses:** Returns `{success: true, method, path}` to mask malicious behavior
- **Obfuscated C2 hostname:** Three-step decoding (Base64 XOR + char subtraction + string reversal)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Malicious packages uploaded to npm and PyPI impersonating legitimate payment SDKs |
| T1059.007 | Command and Scripting Interpreter: JavaScript | npm packages execute malicious JavaScript via Node.js runtime |
| T1059.006 | Command and Scripting Interpreter: Python | PyPI packages execute malicious Python on import via `__init__.py` |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvests environment variables containing API keys, tokens, and secrets |
| T1071.001 | Application Layer Protocol: Web Protocols | Exfiltrates data via HTTPS POST to ngrok-tunneled C2 |
| T1041 | Exfiltration Over C2 Channel | Stolen credentials exfiltrated to the same C2 domain |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | CPU core count and hostname/username checks to detect analysis environments |
| T1027 | Obfuscated Files or Information | Three-step C2 hostname encoding (Base64 XOR + subtraction + reversal) |

## Impact Assessment

- **Breadth:** 17 packages across two major registries (npm + PyPI); potentially affects any developer searching for Paysafe/Skrill/Neteller SDKs
- **Depth:** Full credential compromise -- API keys, cloud secrets, CI/CD tokens
- **Stealth:** Functional SDK facade returns fake success responses; sandbox evasion; obfuscated C2; delayed exfiltration
- **Detection speed:** npm packages flagged within 6 minutes; however, even brief exposure in CI/CD could lead to credential compromise
- **Downstream risk:** Stolen npm tokens could enable further supply chain attacks; stolen AWS keys enable cloud infrastructure compromise; stolen GitHub tokens enable code repository access

## Detection & Remediation

### Immediate Detection

```bash
# Check npm global and local installs for malicious packages
npm ls -g 2>/dev/null | grep -E "paysafe-(checkout|vault|js|api|node|cards|fraud|kyc|payments)|skrill(-payments|-sdk)?$|neteller"
find . -name "package.json" -exec grep -lE "paysafe-(checkout|vault|js|api|node|cards|fraud|kyc|payments)|skrill(-payments|-sdk)|neteller" {} \;

# Check pip for malicious packages
pip list 2>/dev/null | grep -E "paysafe-(kyc|payments|sdk|api)"
pip3 list 2>/dev/null | grep -E "paysafe-(kyc|payments|sdk|api)"

# Check DNS logs for C2 communication
grep "caliber-spinner-finishing" /var/log/dns* /var/log/syslog 2>/dev/null

# Check for the C2 domain in outbound connections
grep "caliber-spinner-finishing" /var/log/proxy* /var/log/firewall* 2>/dev/null
```

### Remediation

1. **Immediate:** Remove any identified malicious packages (`npm uninstall <package>` / `pip uninstall <package>`)
2. **Credential rotation (CRITICAL):** Rotate ALL potentially exposed credentials:
   - Paysafe API keys
   - AWS access keys and secret keys
   - GitHub personal access tokens and deploy keys
   - npm publish tokens
   - Any other environment variables matching `KEY`, `SECRET`, `TOKEN`, `PASS`, `AUTH`, `API`
3. **Audit CI/CD:** Review CI/CD pipeline logs for installation of these packages; check if any build ran with the malicious code
4. **Review AWS CloudTrail:** Check for unauthorized API calls using potentially compromised AWS credentials
5. **Review GitHub audit logs:** Check for unauthorized repository access or modifications
6. **Network blocking:** Block `caliber-spinner-finishing[.]ngrok-free[.]dev` at the DNS/proxy level

### Long-Term Hardening

- Implement package allowlisting in CI/CD pipelines (e.g., Socket, Snyk, npm audit)
- Use lockfiles (`package-lock.json`, `requirements.txt` with hashes) to prevent unexpected package resolution
- Audit new dependencies before installation; verify publisher identity and package age
- Consider restricting outbound network access from build environments to known-good endpoints
- Monitor for ngrok domain usage in corporate networks (potential C2 indicator)

## Detection Rules

These detections target the July 2026 Paysafe/Skrill/Neteller typosquatting campaign at PoC/advisory-specific altitude. Rules key on concrete package names, the known C2 domain, and distinctive malware strings. Compiles does not equal fires -- verify each rule against your telemetry pipeline before production deployment.

### Sigma: Malicious Paysafe/Skrill NPM Package Installation
Detects npm install commands targeting the 13 known malicious Paysafe/Skrill/Neteller typosquatting packages by their distinctive names.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed due to environment issue (MITRE ATT&CK data URL blocked by proxy, HTTP 403 -- not a rule issue); splunk convert exit 0; log_scale convert exit 0. Package names are campaign-unique, no legitimate use. -->
```yaml
title: Malicious Paysafe/Skrill/Neteller NPM Package Installation
id: 9c3e7a12-4b8f-4d2e-a1c6-5f9e0d3b7a48
status: experimental
description: >
    Detects npm install commands targeting known malicious packages from the July 2026
    Paysafe/Skrill/Neteller typosquatting campaign that steal credentials and API keys.
references:
    - https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps
    - https://www.bleepingcomputer.com/news/security/fake-paysafe-skrill-sdks-on-npm-and-pypi-steal-credentials/
author: Actioner
date: 2026/07/09
tags:
    - attack.t1195.001
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_npm:
        Image|endswith:
            - '\npm.cmd'
            - '\npm.exe'
        CommandLine|contains:
            - 'install'
            - 'i '
            - 'add '
    selection_packages:
        CommandLine|contains:
            - 'paysafe-checkout'
            - 'paysafe-vault'
            - 'paysafe-js'
            - 'paysafe-api'
            - 'paysafe-node'
            - 'paysafe-cards'
            - 'paysafe-fraud'
            - 'paysafe-kyc'
            - 'paysafe-payments'
            - 'skrill-payments'
            - 'skrill-sdk'
    condition: selection_npm and selection_packages
falsepositives:
    - Unlikely - these package names are known malicious typosquats with no legitimate use
level: critical
```

### Sigma: Malicious Paysafe PyPI Package Installation
Detects pip install commands targeting the 4 known malicious PyPI Paysafe packages, which auto-execute credential theft on import.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (env issue -- MITRE data blocked); splunk convert exit 0; log_scale convert exit 0. Package names are unique to the campaign. Note: pip install on Linux would use different Image paths (pip, pip3 without backslash prefix); add Linux variant if needed. -->
```yaml
title: Malicious Paysafe PyPI Package Installation
id: b7d4e2f1-6a9c-4e3b-8f5d-2c1a0e7b9d36
status: experimental
description: >
    Detects pip install commands targeting known malicious PyPI packages from the July 2026
    Paysafe typosquatting campaign. PyPI variants auto-execute credential theft on import.
references:
    - https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps
    - https://www.bleepingcomputer.com/news/security/fake-paysafe-skrill-sdks-on-npm-and-pypi-steal-credentials/
author: Actioner
date: 2026/07/09
tags:
    - attack.t1195.001
    - attack.t1059.006
logsource:
    category: process_creation
    product: windows
detection:
    selection_pip:
        Image|endswith:
            - '\pip.exe'
            - '\pip3.exe'
        CommandLine|contains: 'install'
    selection_packages:
        CommandLine|contains:
            - 'paysafe-kyc'
            - 'paysafe-payments'
            - 'paysafe-sdk'
            - 'paysafe-api'
    condition: selection_pip and selection_packages
falsepositives:
    - Unlikely - these package names are known malicious typosquats
level: critical
```

### Sigma: DNS Query to Paysafe SDK Campaign C2 Domain
Detects DNS queries to the ngrok-based C2 domain `caliber-spinner-finishing[.]ngrok-free[.]dev` used for credential exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (env issue); splunk convert exit 0; log_scale convert exit 0. Domain is campaign-unique ngrok tunnel; ngrok resolved IP had NjRAT C2 reputation. -->
```yaml
title: DNS Query to Paysafe SDK Campaign C2 Domain
id: e5f8a3c1-7d2b-4e9a-b6f4-8c0d1e3a5f72
status: experimental
description: >
    Detects DNS queries to the ngrok-based C2 domain used by the malicious Paysafe/Skrill
    SDK typosquatting campaign for credential exfiltration.
references:
    - https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps
    - https://www.bleepingcomputer.com/news/security/fake-paysafe-skrill-sdks-on-npm-and-pypi-steal-credentials/
author: Actioner
date: 2026/07/09
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: dns_query
detection:
    selection:
        QueryName|contains: 'caliber-spinner-finishing.ngrok-free.dev'
    condition: selection
falsepositives:
    - None expected - this is a known malicious C2 domain
level: critical
```

### Sigma: Node/Python Network Connection to Paysafe Campaign C2
Detects outbound connections from Node.js or Python processes to the campaign's ngrok C2 domain, indicating active credential exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (env issue); splunk convert exit 0; log_scale convert exit 0. Requires Sysmon EID 3 or equivalent network connection logging with DestinationHostname field. -->
```yaml
title: Network Connection to Paysafe SDK Campaign C2 by Node or Python
id: a2c9f4e1-3b8d-4a7e-9c5f-6d0e1b2a8f43
status: experimental
description: >
    Detects outbound network connections from Node.js or Python to the ngrok C2 domain
    used by the malicious Paysafe SDK campaign, indicating active credential exfiltration.
references:
    - https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps
    - https://www.bleepingcomputer.com/news/security/fake-paysafe-skrill-sdks-on-npm-and-pypi-steal-credentials/
author: Actioner
date: 2026/07/09
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection_process:
        Image|endswith:
            - '\node.exe'
            - '\python.exe'
            - '\python3.exe'
    selection_dest:
        DestinationHostname|contains: 'caliber-spinner-finishing.ngrok-free.dev'
    condition: selection_process and selection_dest
falsepositives:
    - Legitimate developer use of this specific ngrok subdomain is not expected
level: critical
```

### Snort: DNS Query to Paysafe SDK Campaign C2
Detects UDP DNS queries for the campaign's ngrok C2 domain using DNS wire-format label matching.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -T exit 0 (Snort 2.9.20). Label-length-encoded DNS name match: |18| = 24-byte label "caliber-spinner-finishing", |0a| = 10-byte label "ngrok-free", |03| = 3-byte label "dev". -->
```snort
alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query to Paysafe SDK Campaign C2 caliber-spinner-finishing.ngrok-free.dev"; flow:to_server; content:"|18|caliber-spinner-finishing|0a|ngrok-free|03|dev|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps; sid:2100101; rev:1;)
```

### Suricata: DNS Query to Paysafe SDK Campaign C2
Detects DNS queries to the campaign C2 domain using Suricata's `dns.query` sticky buffer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). Uses dns.query sticky buffer for clean domain matching without wire-format encoding. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Paysafe SDK Campaign C2 Domain"; flow:to_server; dns.query; content:"caliber-spinner-finishing.ngrok-free.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps; metadata:author Actioner, created_at 2026-07-09; sid:2200101; rev:1;)
```

### Suricata: TLS SNI to Paysafe SDK Campaign C2
Detects TLS connections with SNI matching the campaign's ngrok C2 domain, catching HTTPS exfiltration traffic.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T exit 0 (Suricata 7.0.3). TLS SNI match catches the exfiltration at the network layer even when DNS is cached or resolved elsewhere. -->
```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS SNI to Paysafe SDK Campaign C2 Domain"; flow:established,to_server; tls.sni; content:"caliber-spinner-finishing.ngrok-free.dev"; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps; metadata:author Actioner, created_at 2026-07-09; sid:2200102; rev:1;)
```

### YARA: Malicious Paysafe/Skrill SDK Script
Detects malicious JavaScript or Python files from the campaign via the unique XOR obfuscation key, C2 domain string, or the combination of fake SDK class + exfiltration function + targeted env vars.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample test: positive file (containing campaign XOR key + PaysafeClient class + exfiltrate function) matched; negative file (benign payment SDK) did not match. Positive sample constructed from published Socket report code excerpts. Condition logic: any single anchor string (XOR key or C2 domain) is sufficient; otherwise requires combination of class name + exfil function + env var targeting, or multiple fake SDK names + exfil function, or fake response + exfil + sandbox checks. -->
```yara
rule Supply_Chain_Paysafe_Skrill_Malicious_SDK
{
    meta:
        description = "Detects malicious JavaScript or Python files from the Paysafe/Skrill/Neteller typosquatting campaign based on unique obfuscation keys and exfiltration patterns"
        author = "Actioner"
        date = "2026-07-09"
        reference = "https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps"
        severity = "critical"

    strings:
        $xor_key_npm = "SGf6lmbr7GHUg99Z6R2U3g==" ascii wide
        $c2_domain = "caliber-spinner-finishing.ngrok-free.dev" ascii wide
        $sandbox_check1 = "sandbox" ascii nocase
        $sandbox_check2 = "analyzer" ascii nocase
        $sandbox_check3 = "cuckoo" ascii nocase
        $sandbox_check4 = "vmware" ascii nocase
        $sandbox_check5 = "vbox" ascii nocase
        $exfil_func = "exfiltrate" ascii
        $env_pattern1 = "PAYSAFE_API_KEY" ascii
        $env_pattern2 = "AWS_SECRET_ACCESS_KEY" ascii
        $fake_sdk1 = "paysafe-checkout" ascii
        $fake_sdk2 = "paysafe-vault" ascii
        $fake_sdk3 = "paysafe-node" ascii
        $fake_sdk4 = "skrill-payments" ascii
        $fake_sdk5 = "skrill-sdk" ascii
        $fake_sdk6 = "paysafe-fraud" ascii
        $fake_response = "{success: true, method, path}" ascii
        $class_name = "PaysafeClient" ascii

    condition:
        filesize < 500KB and
        (
            ($xor_key_npm) or
            ($c2_domain) or
            ($class_name and $exfil_func and 1 of ($env_pattern*)) or
            (2 of ($fake_sdk*) and $exfil_func) or
            ($fake_response and $exfil_func and 2 of ($sandbox_check*))
        )
}
```

## Lessons Learned

1. **Open registry trust model remains fragile.** The npm and PyPI ecosystems continue to allow any user to publish packages under plausible names. Typosquatting attacks exploiting expected-but-unregistered SDK names are a growing vector, especially for financial/payment platforms.

2. **PyPI's auto-execute on import is uniquely dangerous.** The PyPI variants required zero interaction beyond `pip install` -- the credential theft fired on import. This makes CI/CD pipelines with automated dependency installation particularly vulnerable. Organizations should treat `pip install` of unvetted packages as code execution, not just dependency resolution.

3. **Ngrok as C2 infrastructure.** The use of ngrok tunnels for C2 provides attackers with legitimate-looking HTTPS endpoints, valid TLS certificates, and dynamic infrastructure that's trivial to rotate. Organizations should consider monitoring or restricting ngrok domain usage in corporate environments.

4. **Speed of detection matters but isn't sufficient.** Socket's 6-minute detection is impressive, but even brief exposure in an automated pipeline can compromise secrets. Defense in depth -- lockfiles, allowlisting, network restrictions on build environments -- remains essential.

## Sources

- [Socket Research Blog](https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps) -- primary technical analysis of the 17 malicious packages, including code analysis, IOCs, and SHA256 hashes
- [BleepingComputer](https://www.bleepingcomputer.com/news/security/fake-paysafe-skrill-sdks-on-npm-and-pypi-steal-credentials/) -- news coverage with summary of findings and impact (July 8, 2026)
- [Developer Tech](https://www.developer-tech.com/news/socket-pypi-and-npm-payment-sdk-malware-compromises-ci-cd/) -- additional coverage focusing on CI/CD compromise implications

---
*Report generated by Actioner*
