# Technical Analysis Report: ChocoPoC RAT -- Trojanized PoC Exploit Campaign (2026-07-02)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-07-02
Version: 1.0 (FINAL)
<!-- revision: Applied critic verdicts. Fixed all five Sigma rules: removed product:linux restriction (malware targets both Linux and Windows); changed Mapbox C2 rule to proxy logsource; changed DoH rule to dns_query logsource; tightened gradient file detection to require skytext in path; added os.environ caveat to env-var rule; downgraded confidence on gradient(medium), env-var(medium), Mapbox-C2(medium), DoH(low). Added missing Suricata sid:2200007 and Snort sid:2100006 for rdraa account. Broke out per-rule confidence in Suricata/Snort prose. Fixed YARA permissive conditions: cmd_hola+cmd_dormir now requires a third non-Spanish string; raised 4-of-them to 6-of-them. Fixed T1132.001→T1027 in ATT&CK mapping. Added note on SEKOIA-IO Community GitHub link. -->

## Executive Summary

ChocoPoC is a Python-based Remote Access Trojan (RAT) distributed via trojanized proof-of-concept (PoC) exploit repositories on GitHub, targeting security researchers, pentesters, and red teamers. Discovered jointly by Sekoia and YesWeHack on July 1, 2026, the campaign does not embed malware directly in exploit code but instead poisons the dependency chain: cloning a fake PoC repo installs the `frint` PyPI package, which pulls `skytext` as a dependency. The `skytext` package contains a compiled native extension (`gradient.so` on Linux, `gradient.pyd` on Windows) that XOR-decrypts and decompresses embedded Python code using the key `EXPLOIT_POC.PY`. The decrypted downloader retrieves the final ChocoPoC payload from a Mapbox dataset API endpoint -- a dead-drop technique that leverages domain fronting through `api.mapbox[.]com` and DNS-over-HTTPS via `cloudflare-dns[.]com` and `dns.alidns[.]com` to evade traditional network monitoring. Data exfiltration uses both Mapbox datasets and a dedicated HTTP upload server at `91.132.163[.]78:8001`. The RAT features Spanish-language command names (`hola`, `dormir`, `browserdata`), anti-recursion environment variables, and a hash-based execution gate that only activates when the trigger file `EXPLOIT_POC.py` is present. At least seven GitHub repositories across two campaign waves (2025 and 2026) have been identified, with the `skytext` package alone recording approximately 2,400 downloads. As of publication, the malware infrastructure remains live.

## Background: Fake PoC Exploits as an Attack Vector

Security researchers routinely clone PoC exploit repositories from GitHub to validate vulnerabilities. This practice creates a high-value attack surface: researchers often execute untrusted code in environments containing sensitive tools, credentials, and access to production networks. The ChocoPoC campaign exploits this workflow by publishing convincing PoC repositories for high-profile CVEs. The repositories appear legitimate but include a `requirements.txt` that pulls the trojanized `frint` package from PyPI. Sekoia assesses with high confidence that the attacker used compromised accounts -- credentials for publisher emails appeared in leak databases and infostealer logs -- to publish both the malicious PyPI packages and the GitHub PoC repositories.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025 (est.) | Earlier campaign wave using `slogsec` and `logcrypt.cryptography` packages, Mapbox accounts `mattallahsaed` and `rdraa` |
| 2025 (est.) | GitHub user `lincemorado97` publishes PoC repos for CVE-2025-64446, CVE-2025-55182, CVE-2025-14847 |
| 2026 (est.) | Second campaign wave using `frint` and `skytext` packages, Mapbox accounts `frankley` and `james09790` |
| 2026 (est.) | GitHub users `ogenich` and `bolubey` publish PoC repos for CVE-2026-10520, CVE-2026-48908, CVE-2026-0257, CVE-2026-50751 |
| 2026-03-25 | Download spike correlated with Langflow RCE disclosure |
| 2026-05-05 | Download spike correlated with Linux Copy Fail KEV listing |
| 2026-07-01 | Sekoia and YesWeHack publish joint findings; infrastructure still live |
| 2026-07-02 | BleepingComputer publishes coverage |

## Root Cause: Supply Chain Poisoning via PyPI Dependencies

The attack begins when a victim clones one of the trojanized PoC repositories from GitHub. The `requirements.txt` or `setup.py` in the repository specifies `frint` as a dependency. Installing `frint` via pip automatically pulls the `skytext` package, which bundles a compiled native Python extension (`gradient.so` for Linux, `gradient.pyd` for Windows). When the PoC script is executed, the native extension activates and performs the following chain: XOR-decrypt five embedded compressed Python scripts using the key `b"EXPLOIT_POC.PY"`, decompress them via zlib, and execute the resulting downloader. The downloader retrieves the final ChocoPoC RAT payload from a Mapbox dataset API endpoint.

## Technical Analysis of the Malicious Payload

### 1. Delivery Chain: PyPI Package Poisoning

The infection relies on a three-layer package chain:

1. **frint** (PyPI) -- the entry package specified as a dependency in trojanized PoC repos
2. **skytext** (PyPI) -- pulled as a dependency of frint; contains the compiled native extension
3. **gradient.so / gradient.pyd** -- the native extension inside skytext that decrypts and bootstraps the RAT

Earlier campaign waves used alternative package names: `slogsec` and `logcrypt.cryptography`, with very similar source code delivering the same ChocoPoC payload.

### 2. Native Extension: gradient.so / gradient.pyd

The compiled extension (`gradient.so` on Linux, `gradient.pyd` on Windows) serves as the initial execution gate and decryptor:

- **Execution gate**: Only activates when a file matching `EXPLOIT_POC.py` (hash `0xF4835C9C`) is present as a loaded module, ensuring the malware only triggers during PoC execution
- **Decryption**: XOR-decrypts five embedded zlib-compressed Python scripts using the 14-byte key `b"EXPLOIT_POC.PY"`
- **Anti-recursion**: Sets environment variable `ZEBUWIAKGPHOQAP006=PTsjBGKQUxZorq2` or `JKHWQVEKRASDF12=JKHKJ23VAS8DF9` to prevent re-infection
- **Anti-debugging (Windows)**: Calls `CheckRemoteDebuggerPresent`, inspects hardware breakpoints (Dr0-Dr3 via `GetThreadContext`), uses dynamic API resolution via PEB walking with export table hashing (seed `0x1D4E`)
- **Persistence artifacts**: Drops `distutils-precedence.pth`, `_distutils_hack/override.py`, `_distutils_hack/__init__.py`, and `choco.py` (stage 2 downloader)
- **Timestomping**: Applied to dropped files to hinder forensic timeline analysis

### 3. C2 Infrastructure: Mapbox Dead Drop and DNS-over-HTTPS

ChocoPoC uses a sophisticated C2 scheme that abuses legitimate services:

| Component | Detail |
|-----------|--------|
| Dead-drop service | Mapbox Datasets API (`api.mapbox[.]com`) |
| Dataset ID (2026) | `cmor0tcxf008i1mmpd7apt903` |
| Feature key (2026) | `dm370543acmdopk296nahbtua` |
| Mapbox account (2026) | `frankley` |
| Mapbox account (2026 alt.) | `james09790` |
| Mapbox accounts (2025) | `mattallahsaed`, `rdraa` |
| DNS resolution | DNS-over-HTTPS via `cloudflare-dns[.]com` and `dns.alidns[.]com` |
| Upload server | `91.132.163[.]78:8001` |
| Upload endpoint | `/assets/static/bundle.ext.min.de5b2bc9.js` |

The dead-drop URL pattern for payload retrieval:
`hxxps://api.mapbox[.]com/datasets/v1/frankley/cmor0tcxf008i1mmpd7apt903/features/dm370543acmdopk296nahbtua`

### 4. RAT Capabilities

ChocoPoC uses Spanish-language command names, suggesting a Spanish-speaking developer:

| Command | Function |
|---------|----------|
| `hola` | System reconnaissance -- collects host info, network config, running processes |
| `cmd` | Arbitrary shell command execution |
| `python` | Dynamic Python code execution |
| `get` | File/folder staging and exfiltration |
| `browserdata` | Browser credential harvesting (passwords, cookies, autofill, history) |
| `dormir` | Adjust beacon/sleep interval |

**Browser credential theft** targets: Google Chrome, Brave, Microsoft Edge, Mozilla Firefox.

**File search** targets: `.txt`, `.md`, `data.db`, `local-store.db` files.

**Shell history collection**: `.bash_history`, `.zsh_history`.

**Network enumeration**: Network configuration, active connections, routing tables.

**Process listing**: Full process enumeration for situational awareness.

### 5. Exfiltration Methods

- **Small data**: Uploaded to Mapbox datasets via the API (using stolen/created API tokens)
- **Large data**: Chunked upload to `hxxp://91.132.163[.]78:8001/assets/static/bundle.ext.min.de5b2bc9.js`

### 6. GitHub Distribution Repositories

| GitHub Account | Repository | CVE Lure |
|----------------|-----------|----------|
| `lincemorado97` | CVE-2025-64446_CVE-2025-58034 | FortiWeb path traversal |
| `lincemorado97` | CVE-2025-55182_CVE-2025-66478 | React2Shell |
| `lincemorado97` | CVE-2025-14847 | MongoBleed |
| `ogenich` | CVE-2026-10520 | Ivanti Sentry OS command injection |
| `ogenich` | CVE-2026-48908 | Joomla SP Page Builder RCE |
| `bolubey` | CVE-2026-0257 | PAN-OS authentication bypass |
| `bolubey` | CVE-2026-50751 | Check Point VPN auth bypass |

**Committer emails (likely compromised)**:
- `21104040041[at]student.uin-suka[.]ac[.]id` (lincemorado97)
- `200111085[at]ogrenci.ibu[.]edu[.]tr` (ogenich)

**PyPI publisher emails (compromised)**:
- `leechuun[at]gmail[.]com`
- `faberhun[at]gmail[.]com`

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` replacing `https://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots
> - Emails: `[at]` replacing `@`

### File Hashes

| Type | Value | Description |
|------|-------|-------------|
| SHA256 | `93739477cd379adef95126b22758c0e644282d2028dd297328ce856fa111dd06` | skytext v1.1.0 wheel |
| SHA256 | `17997e9e0256d0f5d5d21a4852c37f16b338e4bb9c2bec09bdfd822b24aa76b4` | frint v0.1.2 wheel |
| SHA256 | `5abd45d6f4a1705dca55d882f017d4768888dce9ad99cea40b3da35c23de5cae` | slogsec wheel (earlier campaign) |
| SHA256 | `40569318e89db751ff3886b2617d990d8a343f0d1d8727b7f978a28129ca36bc` | gradient.pyd (Windows native extension) |
| SHA256 | `320b29844892e3c59bc6fcb07e701b2b3230a37cb4a13176174e9e294ec6d43e` | gradient.so (Linux native extension) |

### Package / Software Level

| Package | Registry | Description |
|---------|----------|-------------|
| `frint` (v0.1.2) | PyPI | Entry trojanized package; dependency in fake PoC repos |
| `skytext` (v1.1.0) | PyPI | Contains gradient.so/gradient.pyd; ~2,400 downloads |
| `slogsec` | PyPI | Earlier campaign variant; similar code |
| `logcrypt.cryptography` | PyPI | Earlier campaign variant |

### File System

| Platform | Path / Artifact | Description |
|----------|----------------|-------------|
| Linux/Windows | `gradient.so` / `gradient.pyd` | Native extension in skytext package |
| Linux/Windows | `distutils-precedence.pth` | Setuptools hook dropped by extension |
| Linux/Windows | `_distutils_hack/override.py` | Dropped persistence component |
| Linux/Windows | `_distutils_hack/__init__.py` | Trojanized package component |
| Linux/Windows | `choco.py` | Stage 2 downloader |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP:Port | `91.132.163[.]78:8001` | Upload/exfiltration server |
| Domain | `api.mapbox[.]com` | Abused for C2 dead-drop via datasets API |
| Domain | `cloudflare-dns[.]com` | DNS-over-HTTPS resolver |
| Domain | `dns.alidns[.]com` | DNS-over-HTTPS resolver (alternative) |
| URL | `hxxps://api.mapbox[.]com/datasets/v1/frankley/cmor0tcxf008i1mmpd7apt903/features/dm370543acmdopk296nahbtua` | Payload dead-drop URL (2026 campaign) |
| URL | `hxxp://91.132.163[.]78:8001/assets/static/bundle.ext.min.de5b2bc9.js` | Exfiltration upload endpoint |

### Mapbox API Accounts (Compromised/Created — tokens redacted for push protection)

| Account | Token Prefix | Campaign |
|---------|-------------|----------|
| `frankley` | `pk.eyJ1IjoiZnJhbmtsZXki...` (public key) | 2026 |
| `james09790` | `sk.eyJ1IjoiamFtZXMwOTc5MA...` (secret key) | 2026 |
| `mattallahsaed` | `pk.eyJ1IjoibWF0dGFsbGFo...` (public key) | 2025 |
| `rdraa` | `sk.eyJ1IjoicmRyYWEi...` (secret key) | 2025 |

<!-- Full tokens available in the Sekoia report; redacted here to pass GitHub push protection -->

### Behavioral

- Environment variables `ZEBUWIAKGPHOQAP006` or `JKHWQVEKRASDF12` set on compromised hosts
- Files named `EXPLOIT_POC.py`, `exploit.py`, or `exploit_poc.py` trigger the infection chain
- Python processes making HTTPS requests to `api.mapbox[.]com/datasets/v1/` with specific account paths
- Python processes performing DNS-over-HTTPS queries to `cloudflare-dns[.]com` or `dns.alidns[.]com`
- Outbound HTTP connections to `91.132.163[.]78:8001`
- Creation of `distutils-precedence.pth` and `_distutils_hack/` directory in site-packages

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Malicious PyPI packages (frint, skytext) poisoning PoC exploit dependency chains |
| T1059.006 | Command and Scripting Interpreter: Python | ChocoPoC RAT executes arbitrary Python code via `python` command; gradient.so decrypts and executes embedded Python |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Browser credential theft from Chrome, Brave, Edge, Firefox (passwords, cookies, autofill, history) |
| T1041 | Exfiltration Over C2 Channel | Stolen data exfiltrated via Mapbox datasets API and HTTP upload server |
| T1102 | Web Service | Mapbox dataset API abused as dead-drop for C2 payload retrieval and data exfiltration |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS communication with Mapbox API; HTTP upload to exfiltration server |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | RSA public key used for encrypting exfiltrated data |
| T1027 | Obfuscated Files or Information | XOR encryption with key `EXPLOIT_POC.PY` and zlib compression for embedded payloads |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | Anti-debugging via `CheckRemoteDebuggerPresent`, hardware breakpoint inspection, PEB walking |
| T1070.006 | Indicator Removal: Timestomp | Timestomping applied to dropped files |
| T1083 | File and Directory Discovery | File search targeting .txt, .md, .db files |
| T1057 | Process Discovery | Process enumeration via `hola` command |
| T1016 | System Network Configuration Discovery | Network configuration collection |

## Impact Assessment

ChocoPoC targets security researchers and penetration testers -- a high-value demographic with access to:

- **Vulnerability intelligence**: Unpublished exploits, 0-day research, bug bounty findings
- **Infrastructure access**: VPN credentials, SSH keys, cloud tokens for client networks
- **Credential stores**: Browser-saved passwords for security platforms, ticketing systems, source code repositories
- **Shell histories**: Command-line artifacts revealing internal infrastructure, hostnames, credentials
- **Sensitive documents**: Reports, assessments, and database files containing client data

The campaign's use of compromised academic email accounts for GitHub and PyPI publishing, combined with domain fronting through Mapbox, makes attribution difficult and infrastructure takedown slow. As of July 1, 2026, Sekoia and YesWeHack confirm the infrastructure remains active.

## Detection & Remediation

### Immediate Detection

```bash
# Check for anti-recursion environment variables (indicator of active compromise)
env | grep -E 'ZEBUWIAKGPHOQAP006|JKHWQVEKRASDF12'

# Check for malicious packages installed
pip list 2>/dev/null | grep -iE 'frint|skytext|slogsec|logcrypt'
pip3 list 2>/dev/null | grep -iE 'frint|skytext|slogsec|logcrypt'

# Check for gradient.so in site-packages
find /usr -name "gradient.so" -o -name "gradient.pyd" 2>/dev/null
find ~/.local -name "gradient.so" -o -name "gradient.pyd" 2>/dev/null

# Check for distutils-precedence.pth hook
find /usr -name "distutils-precedence.pth" 2>/dev/null
find ~/.local -name "distutils-precedence.pth" 2>/dev/null

# Check for choco.py stage 2
find / -name "choco.py" -newer /etc/hostname 2>/dev/null

# Check network connections to known C2
ss -tnp | grep '91.132.163.78'

# Check for cloned malicious repos
find ~ -path "*CVE-2025-64446*" -o -path "*CVE-2025-55182*" -o -path "*CVE-2025-14847*" \
  -o -path "*CVE-2026-10520*" -o -path "*CVE-2026-48908*" -o -path "*CVE-2026-0257*" \
  -o -path "*CVE-2026-50751*" 2>/dev/null
```

### Remediation

1. **Contain**: Block `91.132.163[.]78` at the network perimeter; consider blocking or monitoring unusual Mapbox dataset API access patterns from non-GIS workloads
2. **Remove packages**: `pip uninstall frint skytext slogsec logcrypt.cryptography`; remove any `gradient.so`/`gradient.pyd` and `distutils-precedence.pth` artifacts from site-packages
3. **Kill active processes**: Terminate any Python processes with the anti-recursion environment variables set
4. **Delete cloned repos**: Remove any of the seven identified malicious PoC repositories
5. **Rotate credentials**: Change all browser-saved passwords, regenerate SSH keys, rotate API tokens and cloud credentials; assume all saved browser credentials are compromised
6. **Review shell history**: Check `.bash_history` and `.zsh_history` for sensitive commands that may have been exfiltrated
7. **Audit PyPI usage**: Review `requirements.txt` and `setup.py` in all recently cloned repositories for unexpected dependencies

### Long-Term Hardening

- Run untested PoC exploits in isolated VMs or containers with no access to credential stores
- Use hash verification on known-good PoC repositories before execution
- Monitor PyPI package installations for packages not in an approved allowlist
- Deploy DNS monitoring to detect DNS-over-HTTPS usage from unexpected applications
- Monitor for connections to `api.mapbox[.]com/datasets/` from development environments where GIS work is not expected

## Detection Rules

These detections target the ChocoPoC RAT campaign's specific artifacts: malicious PyPI packages, native extension files, anti-recursion environment variables, Mapbox C2 dead-drop communication, DNS-over-HTTPS resolver usage, and exfiltration to the known upload server. PoC/advisory-specific altitude; compiles does not equal fires -- verify in your pipeline before production deployment.

### Sigma: Malicious PyPI Package Installation (frint/skytext)

Detects pip installation of the known malicious PyPI packages (frint, skytext, slogsec, logcrypt) used in the ChocoPoC supply chain.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. sigma check failed due to MITRE ATT&CK data fetch error (proxy 403), not a rule defect. IOC-anchored: package names are unique malware artifacts. FP risk low: frint/skytext are not common legitimate package names. Revision: removed product:linux — malware ships gradient.pyd for Windows; added Windows pip paths. -->
```yaml
title: ChocoPoC RAT - Malicious PyPI Package Installation (frint/skytext)
id: 4c8e2a1f-9b37-4d5e-a6c8-1e2f3b4d5a6c
status: experimental
description: >
    Detects pip installation of known malicious PyPI packages (frint, skytext,
    slogsec, logcrypt.cryptography) associated with the ChocoPoC RAT campaign
    targeting security researchers via trojanized PoC exploit repositories.
references:
    - https://www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits
    - https://www.bleepingcomputer.com/news/security/new-chocopoc-malware-targets-researchers-via-trojanized-poc-exploits/
author: Actioner
date: 2026/07/02
tags:
    - attack.t1195.001
    - attack.t1059.006
logsource:
    category: process_creation
detection:
    selection_pip:
        Image|endswith:
            - '/pip'
            - '/pip3'
            - '\pip.exe'
            - '\pip3.exe'
        CommandLine|contains:
            - 'install'
    selection_package:
        CommandLine|contains:
            - 'frint'
            - 'skytext'
            - 'slogsec'
            - 'logcrypt'
    condition: selection_pip and selection_package
falsepositives:
    - Legitimate packages with these names in private registries (unlikely)
level: critical
```

### Sigma: Gradient Native Extension File Creation

Detects creation of gradient.so or gradient.pyd files within the skytext package directory, the native extension deployed by the ChocoPoC campaign.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. sigma check failed (proxy). Requires file event telemetry (e.g., auditd, Sysmon for Linux, Sysmon on Windows). Revision: removed product:linux (gradient.pyd exists for Windows); tightened detection to require 'skytext' in path — bare 'site-packages' alternative matched any gradient.so in any package including legitimate ML packages. Downgraded to medium per critic. -->
```yaml
title: ChocoPoC RAT - Gradient Native Extension File Creation
id: 7d9f3e2c-1a4b-5c6d-8e0f-2a3b4c5d6e7f
status: experimental
description: >
    Detects creation of gradient.so or gradient.pyd files within the skytext
    package path, associated with the ChocoPoC RAT campaign. The skytext
    package deploys these compiled native extensions that decrypt and execute
    embedded malicious Python code.
references:
    - https://www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits
    - https://www.bleepingcomputer.com/news/security/new-chocopoc-malware-targets-researchers-via-trojanized-poc-exploits/
author: Actioner
date: 2026/07/02
tags:
    - attack.t1195.001
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '/gradient.so'
            - '\gradient.so'
            - '/gradient.pyd'
            - '\gradient.pyd'
        TargetFilename|contains: 'skytext'
    condition: selection
falsepositives:
    - Legitimate Python packages named skytext using gradient extensions (unlikely)
level: high
```

### Sigma: Anti-Recursion Environment Variable

Detects explicit shell commands referencing the ChocoPoC anti-recursion environment variables. Only catches `export`/`env`/`set` invocations -- the malware sets these via `os.environ` in Python, which does not populate CommandLine; pair with YARA for file-level detection.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. sigma check failed (proxy). Revision: removed product:linux (Windows variant exists); downgraded from high to medium — the malware sets env vars via os.environ which won't appear in CommandLine of process_creation events; this rule only fires when the vars appear in explicit shell commands (export, env, set). Still useful for shell-based investigation or bash/zsh wrapper scenarios. -->
```yaml
title: ChocoPoC RAT - Anti-Recursion Environment Variable
id: 8e0a4f3d-2b5c-6d7e-9f1a-3b4c5d6e7f8a
status: experimental
description: >
    Detects shell commands referencing the anti-recursion environment variables
    set by the ChocoPoC RAT. Note: the malware typically sets these via Python
    os.environ, which does not appear in process_creation CommandLine; this rule
    catches explicit export/env/set commands referencing these unique strings.
references:
    - https://www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits
author: Actioner
date: 2026/07/02
tags:
    - attack.t1059.006
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'ZEBUWIAKGPHOQAP006'
            - 'JKHWQVEKRASDF12'
    condition: selection
falsepositives:
    - None expected - these are unique malware-specific environment variable names
level: high
```

### Sigma: Mapbox Dataset API C2 Communication

Detects proxy/web log entries showing requests to Mapbox datasets API with attacker-controlled account paths used for C2 dead-drop retrieval.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. sigma check failed (proxy). Revision: changed logsource from process_creation to proxy — Python uses requests/urllib internally so the Mapbox URL never appears in CommandLine; proxy/web logs capture the actual HTTP request. Removed product:linux (cross-platform). Downgraded to medium: IOC-anchored but logsource coverage varies. -->
```yaml
title: ChocoPoC RAT - Mapbox Dataset API C2 Communication
id: 9f1b5a4e-3c6d-7e8f-0a2b-4c5d6e7f8a9b
status: experimental
description: >
    Detects proxy or web log entries showing requests to Mapbox datasets API
    endpoints used by ChocoPoC RAT as a dead-drop resolver for C2 payload
    retrieval and data exfiltration. The URL does not appear in process
    CommandLine (Python uses requests/urllib internally); requires proxy logs.
references:
    - https://www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits
    - https://www.bleepingcomputer.com/news/security/new-chocopoc-malware-targets-researchers-via-trojanized-poc-exploits/
author: Actioner
date: 2026/07/02
tags:
    - attack.t1102
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_host:
        c-uri|contains: 'api.mapbox.com/datasets'
    selection_accounts:
        c-uri|contains:
            - '/v1/frankley/'
            - '/v1/mattallahsaed/'
            - '/v1/rdraa/'
            - '/v1/james09790/'
    condition: selection_host and selection_accounts
falsepositives:
    - Legitimate Mapbox dataset API usage by these specific accounts (extremely unlikely)
level: critical
```

### Sigma: DNS-over-HTTPS Resolver Usage from Python

Detects DNS queries for DoH resolver domains originating from Python processes. Hunt rule -- legitimate Python tools also use DoH; scope to researcher workstations and pair with the Mapbox C2 anchor rules.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0. sigma check failed (proxy). Revision: changed logsource from process_creation to dns_query — Python DoH connections don't appear in CommandLine (uses requests/urllib internally). Removed product:linux (cross-platform). Downgraded to low: this is a behavioral TTP rule, not IOC-specific; legitimate Python tools (httpx, dnspython, doh-proxy) query these same domains. -->
```yaml
title: ChocoPoC RAT - DNS-over-HTTPS Resolver Usage from Python
id: a02c6b5f-4d7e-8f9a-1b3c-5d6e7f8a9b0c
status: experimental
description: >
    Detects DNS queries for DoH resolver domains (cloudflare-dns.com,
    dns.alidns.com) that ChocoPoC uses to resolve C2 infrastructure while
    evading traditional DNS monitoring. Hunt rule: legitimate Python tools
    also query these domains; pair with Mapbox C2 account-path detections.
references:
    - https://www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits
author: Actioner
date: 2026/07/02
tags:
    - attack.t1071.001
    - attack.t1573.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'cloudflare-dns.com'
            - 'dns.alidns.com'
    condition: selection
falsepositives:
    - Python-based DNS tools, DoH proxies, or privacy-focused applications using DoH resolvers
    - Browser-level DoH resolution (Firefox, Chrome with DoH enabled)
level: medium
```

### Suricata: ChocoPoC C2 and Exfiltration Network Detection

Seven rules targeting Mapbox dataset API C2 dead-drop patterns (account-specific URI paths for all four accounts), DNS resolution of api.mapbox.com (hunt rule), and HTTP exfiltration to the known upload server at 91.132.163.78:8001. Per-rule confidence: sid:2200001 (DNS api.mapbox.com) is **low/hunt** -- fires on any api.mapbox.com DNS query including legitimate Mapbox SDK usage, and ChocoPoC uses DoH so this misses the actual malware; sid:2200002-2200004,2200007 (account-specific HTTP) are **high**; sid:2200005-2200006 (upload server) are **high** (IP will age).
**Status:** compile ✅ compiles · confidence: high (per-account HTTP rules), low (DNS hunt rule)
<!-- audit: suricata -T exit 0. Revision: added sid:2200007 for rdraa account (was missing); broke out per-rule confidence — sid:2200001 explicitly labeled hunt/low (fires on all api.mapbox.com DNS, thousands/day in Mapbox-using orgs, and ChocoPoC uses DoH bypassing DNS entirely). -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - ChocoPoC RAT Mapbox C2 Dataset API Query [HUNT]"; flow:to_server; dns.query; content:"api.mapbox.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits; metadata:author Actioner, created_at 2026-07-02, confidence low, hunt true; sid:2200001; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChocoPoC RAT Mapbox Dataset C2 Retrieval (frankley)"; flow:established,to_server; http.uri; content:"/datasets/v1/frankley/"; fast_pattern; http.host; content:"api.mapbox.com"; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits; metadata:author Actioner, created_at 2026-07-02; sid:2200002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChocoPoC RAT Mapbox Dataset C2 Retrieval (mattallahsaed)"; flow:established,to_server; http.uri; content:"/datasets/v1/mattallahsaed/"; fast_pattern; http.host; content:"api.mapbox.com"; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits; metadata:author Actioner, created_at 2026-07-02; sid:2200003; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChocoPoC RAT Mapbox Dataset C2 Retrieval (james09790)"; flow:established,to_server; http.uri; content:"/datasets/v1/james09790/"; fast_pattern; http.host; content:"api.mapbox.com"; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits; metadata:author Actioner, created_at 2026-07-02; sid:2200004; rev:1;)

alert http $HOME_NET any -> 91.132.163.78 any (msg:"Actioner - ChocoPoC RAT Exfiltration to Upload Server"; flow:established,to_server; http.uri; content:"/assets/static/bundle.ext.min.de5b2bc9.js"; fast_pattern; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits; metadata:author Actioner, created_at 2026-07-02; sid:2200005; rev:1;)

alert http $HOME_NET any -> 91.132.163.78 8001 (msg:"Actioner - ChocoPoC RAT Upload Server Connection"; flow:established,to_server; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits; metadata:author Actioner, created_at 2026-07-02; sid:2200006; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - ChocoPoC RAT Mapbox Dataset C2 Retrieval (rdraa)"; flow:established,to_server; http.uri; content:"/datasets/v1/rdraa/"; fast_pattern; http.host; content:"api.mapbox.com"; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits; metadata:author Actioner, created_at 2026-07-02; sid:2200007; rev:1;)
```

### Snort: ChocoPoC C2 and Exfiltration Detection

Six rules targeting the known upload server IP:port, exfiltration URI path, and Mapbox dataset account-specific C2 patterns for all four accounts. All IOC-anchored, high confidence.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T exit 0. Revision: added sid:2100006 for rdraa account (was missing). All six rules IOC-anchored. -->
```snort
alert tcp $HOME_NET any -> 91.132.163.78 8001 (msg:"ChocoPoC RAT - Exfiltration to Known Upload Server"; flow:established,to_server; content:"/assets/static/bundle.ext.min.de5b2bc9.js"; fast_pattern; sid:2100001; rev:1; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ChocoPoC RAT - Mapbox Dataset C2 Dead Drop (frankley)"; flow:established,to_server; content:"api.mapbox.com"; content:"/datasets/v1/frankley/"; fast_pattern; sid:2100002; rev:1; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ChocoPoC RAT - Mapbox Dataset C2 Dead Drop (mattallahsaed)"; flow:established,to_server; content:"api.mapbox.com"; content:"/datasets/v1/mattallahsaed/"; fast_pattern; sid:2100003; rev:1; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ChocoPoC RAT - Mapbox Dataset C2 Dead Drop (james09790)"; flow:established,to_server; content:"api.mapbox.com"; content:"/datasets/v1/james09790/"; fast_pattern; sid:2100004; rev:1; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits;)

alert tcp $HOME_NET any -> 91.132.163.78 8001 (msg:"ChocoPoC RAT - Connection to Known Upload Server IP"; flow:established,to_server; sid:2100005; rev:1; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ChocoPoC RAT - Mapbox Dataset C2 Dead Drop (rdraa)"; flow:established,to_server; content:"api.mapbox.com"; content:"/datasets/v1/rdraa/"; fast_pattern; sid:2100006; rev:1; classtype:trojan-activity; reference:url,www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits;)
```

### YARA: ChocoPoC RAT and Gradient Extension Detection

Two rules: Rule 1 detects ChocoPoC RAT scripts/components via anti-recursion markers, Spanish command names (anchored with a non-Spanish string), Mapbox identifiers, and C2 infrastructure strings. Rule 2 detects the gradient.so/gradient.pyd native extension via XOR key and anti-debugging artifacts.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample re-tested after condition tightening. Revision: (1) $cmd_hola+$cmd_dormir were common Spanish words — now requires $cmd_browserdata as a third non-Spanish anchor; (2) raised "4 of them" to "6 of them" to reduce false positives from coincidental partial matches across 20+ strings. Rule 2 unchanged (KEEP). -->
```yara
rule Malware_Python_ChocoPoC_RAT
{
    meta:
        description = "Detects ChocoPoC RAT components via distinctive strings including anti-recursion markers, Spanish-language command names, Mapbox C2 identifiers, and malicious package artifacts"
        author = "Actioner"
        date = "2026-07-02"
        reference = "https://www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits"
        tlp = "WHITE"
        severity = "critical"
        hash_skytext = "93739477cd379adef95126b22758c0e644282d2028dd297328ce856fa111dd06"
        hash_frint = "17997e9e0256d0f5d5d21a4852c37f16b338e4bb9c2bec09bdfd822b24aa76b4"
        hash_gradient_pyd = "40569318e89db751ff3886b2617d990d8a343f0d1d8727b7f978a28129ca36bc"
        hash_gradient_so = "320b29844892e3c59bc6fcb07e701b2b3230a37cb4a13176174e9e294ec6d43e"

    strings:
        $env_anti1 = "ZEBUWIAKGPHOQAP006" ascii
        $env_anti2 = "JKHWQVEKRASDF12" ascii
        $env_val1 = "PTsjBGKQUxZorq2" ascii
        $env_val2 = "JKHKJ23VAS8DF9" ascii

        $cmd_hola = "hola" ascii
        $cmd_dormir = "dormir" ascii
        $cmd_browserdata = "browserdata" ascii

        $mapbox_dataset = "cmor0tcxf008i1mmpd7apt903" ascii
        $mapbox_feature = "dm370543acmdopk296nahbtua" ascii
        $mapbox_user1 = "frankley" ascii
        $mapbox_user2 = "mattallahsaed" ascii
        $mapbox_user3 = "james09790" ascii

        $c2_upload = "91.132.163.78" ascii
        $c2_port = ":8001" ascii
        $c2_path = "/assets/static/bundle.ext.min.de5b2bc9.js" ascii

        $xor_key = "EXPLOIT_POC.PY" ascii

        $pkg_skytext = "skytext" ascii
        $pkg_frint = "frint" ascii
        $stage2 = "choco.py" ascii

        $distutils_hook = "distutils-precedence.pth" ascii

    condition:
        filesize < 5MB and
        (
            (2 of ($env_anti1, $env_anti2, $env_val1, $env_val2)) or
            ($cmd_hola and $cmd_dormir and $cmd_browserdata) or
            (1 of ($mapbox_dataset, $mapbox_feature)) or
            ($c2_upload and $c2_path) or
            ($xor_key and 1 of ($pkg_skytext, $pkg_frint, $stage2)) or
            ($distutils_hook and 1 of ($env_anti*, $cmd_*, $mapbox_*)) or
            (6 of them)
        )
}

rule Malware_Python_ChocoPoC_Gradient_Extension
{
    meta:
        description = "Detects the ChocoPoC gradient.so/gradient.pyd native extension by embedded decryption key and anti-analysis artifacts"
        author = "Actioner"
        date = "2026-07-02"
        reference = "https://www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits"
        tlp = "WHITE"
        severity = "critical"
        hash_gradient_pyd = "40569318e89db751ff3886b2617d990d8a343f0d1d8727b7f978a28129ca36bc"
        hash_gradient_so = "320b29844892e3c59bc6fcb07e701b2b3230a37cb4a13176174e9e294ec6d43e"

    strings:
        $xor_key = "EXPLOIT_POC.PY" ascii
        $env_marker = "ZEBUWIAKGPHOQAP006" ascii
        $hash_gate = { F4 83 5C 9C }
        $api_seed = { 1D 4E }

    condition:
        (uint32(0) == 0x464C457F or uint16(0) == 0x5A4D) and
        filesize < 10MB and
        (
            ($xor_key and $env_marker) or
            ($hash_gate and $api_seed) or
            ($xor_key and ($hash_gate or $api_seed))
        )
}
```

## Lessons Learned

1. **Dependency chains are the real attack surface**: The ChocoPoC campaign demonstrates that reviewing only the PoC script itself is insufficient. The malicious code resides entirely in the dependency chain (`frint` -> `skytext` -> `gradient.so`), making manual code review of the exploit file alone useless for detection.

2. **Legitimate services as C2 infrastructure**: The abuse of Mapbox datasets API for dead-drop C2 combined with DNS-over-HTTPS makes network-based detection significantly harder. Blocking `api.mapbox[.]com` outright may not be feasible in organizations that use Mapbox services. Detection must focus on the specific account paths and dataset IDs.

3. **Compromised accounts amplify trust**: The attacker used stolen credentials (from infostealers and leak databases) to publish packages and repositories, making the supply chain attack harder to attribute and the repositories appear more legitimate.

4. **Security researchers as high-value targets**: This campaign specifically targets the community most likely to clone and execute exploit code. Organizations should enforce that all PoC testing occurs in isolated environments (VMs, containers) with no access to production credentials or browser stores.

## Sources

- [Sekoia Blog: Don't Eat The ChocoPoCs](https://www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits) -- primary technical analysis by Pierre LE BOURHIS, Quentin BOURGUE, and the TDR Team; joint investigation with YesWeHack; published July 1, 2026
- [BleepingComputer: New ChocoPoC malware targets researchers via trojanized PoC exploits](https://www.bleepingcomputer.com/news/security/new-chocopoc-malware-targets-researchers-via-trojanized-poc-exploits/) -- reporting with additional context on the campaign's scope and attribution; published July 2, 2026
- [BleepingComputer: ChocoPoC malware delivered via trojanized exploits on GitHub](https://www.bleepingcomputer.com/news/security/chocopoc-malware-delivered-via-trojanized-exploits-on-github/) -- additional coverage with detail on download statistics and compromised account analysis
- [SEKOIA-IO Community GitHub Repository](https://github.com/SEKOIA-IO/Community) -- Sekoia's IOC and detection rule sharing repository (general repo; no ChocoPoC-specific directory identified at time of publication)

---
*Report generated by Actioner*
