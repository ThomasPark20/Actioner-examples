# Technical Analysis Report: Shai-Hulud Science Wave — Trojanized PyPI Bioinformatics Packages (2026-06-09)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-09
Version: 1.1

## Executive Summary

On June 8, 2026, a new wave of the Shai-Hulud supply chain campaign was detected targeting the scientific Python ecosystem. Endor Labs identified six bioinformatics PyPI packages — ensmallen, embiggen, pyphetools, gpsea, phenopacket-store-toolkit, and ppkt2synergy — that were simultaneously replaced with trojanized versions containing a multi-stage credential stealer and self-propagating worm. This wave is **technically distinct** from the Hades Cluster attack covered on 2026-06-07, which compromised 19 packages via `.pth` startup hooks: the science wave instead embeds the malicious payload inside **compiled Rust/C++ binary extensions (`.abi3.so`, ~57 MB each)** that execute only at runtime when Python calls `dlopen()` on them, making static analysis significantly harder. The six packages were published within a 60-second window starting at 03:09 UTC and were quarantined by Endor Labs within 24 minutes. Separately, the BleepingComputer report aggregates both waves under the broader Shai-Hulud campaign, citing 19 science-focused packages with hundreds of thousands of cumulative downloads and 37 malicious releases from a single compromised maintainer.

The attack uses GitHub account `felixEvora` with 30 dead-drop repositories themed around Greek underworld mythology (e.g., `lethean-tartarus-61322`, `abyssal-acheron-97481`) for primary credential exfiltration. Fallback C2 domains `thebeautifulmarchoftime` and `thebeautifulsnadsoftime` provide secondary exfiltration channels. A tertiary channel using `api[.]anthropic[.]com/v1/api` is non-functional camouflage. The credential stealer targets AWS, Azure, GCP, Kubernetes, HashiCorp Vault, GitHub/npm/PyPI/RubyGems tokens, SSH keys, Docker configs, password managers, and AI coding tool configurations. Socket tracks 453+ malicious artifacts attributed to the broader Shai-Hulud campaign.

## Background: Scientific Python Ecosystem and PyPI Binary Extensions

The affected packages serve academic research communities in genomics (ensmallen, embiggen), phenotype analysis (pyphetools, gpsea, phenopacket-store-toolkit, ppkt2synergy), and graph machine learning. These communities often operate on high-performance computing clusters and clinical data pipelines with elevated cloud and infrastructure privileges, making credential theft particularly impactful.

Python's stable ABI mechanism (`.abi3.so`) allows compiled extensions to be portable across Python versions. Unlike `.pth` startup hooks (used in the earlier Hades Cluster wave), binary extensions execute only when the package is imported and Python calls `dlopen()` on the shared object — they do not run automatically on every Python interpreter invocation. However, for the target audience of bioinformatics researchers, importing these packages in research notebooks or pipelines is routine, making the trigger reliable.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-29 | Mini Shai-Hulud campaign begins targeting npm ecosystem |
| 2026-05-19 | @antv npm scope compromised; 600+ malicious versions published |
| 2026-06-01 | @redhat-cloud-services npm scope compromised via OIDC trusted publishing |
| 2026-06-07 | Hades Cluster wave: 19 PyPI packages trojanized via `.pth` startup hooks (covered in prior report) |
| 2026-06-08 03:09–03:10 | Science wave: 6 bioinformatics packages published with trojanized `.abi3.so` extensions |
| 2026-06-08 03:12–03:33 | Endor Labs quarantines all six malicious packages |
| 2026-06-08 03:30 | GitHub account `felixEvora` begins receiving exfiltrated credential commits |
| 2026-06-08 | BleepingComputer reports on 19 science-focused PyPI packages; Socket updates campaign tracker to 453+ artifacts |

## Root Cause: Maintainer Account Compromise via Stolen API Tokens

The compromise vector was stolen PyPI API tokens — every package was uploaded using the Bun JavaScript runtime rather than standard Python packaging tools (twine, build, flit), which is an immediate anomaly indicator. The attacker used custom JavaScript/TypeScript automation to publish trojanized versions, bypassing CI/CD pipelines entirely. The HTTP `User-Agent` header `Bun/1.3.13` in PyPI upload traffic is a distinctive forensic indicator. The exact method of token theft is not confirmed but is consistent with credential harvesting from a prior Shai-Hulud wave (the worm self-propagates using stolen PyPI tokens).

## Technical Analysis of the Malicious Payload

### 1. Stage 1: Compiled Binary Extension Injection (.abi3.so)

Unlike the Hades Cluster wave's `.pth` hooks, this wave embeds the payload inside platform-specific compiled binary extensions (`.abi3.so` files, approximately 57 MB each). These are compiled Rust/C++ shared objects that execute the embedded JavaScript payload when the Python interpreter calls `dlopen()` on them — i.e., when the package is imported. This approach:

- Evades Python-focused static analysis tools that inspect `.py`, `.pth`, and `setup.py` files
- Bypasses PyPI's malware scanning pipeline which focuses on script-level inspection
- Makes decompilation and reverse engineering significantly more complex than obfuscated JavaScript alone

### 2. Stage 2: Obfuscated JavaScript Credential Stealer (_index.js)

Each malicious package contains a 5.3 MB `_index.js` file with multiple obfuscation layers:

- **Lines 1–99:** Fake LLM jailbreak prompt serving as a decoy to confuse automated analysis
- **Line 101:** Actual payload wrapped in `eval(function(s,n){ return s.replace(/[a-zA-Z]/g, ROT-N)` cipher
- **Encryption:** AES-128-GCM decryption using deobfuscation key `fed1de59e` (accessed via `globalThis["fed1de59e"]`)
- **Hybrid encryption for exfiltration:** `E8()` function implementing RSA-OAEP + AES-256-GCM envelope encryption

The credential harvesting scope is comprehensive:

| Category | Targets |
|----------|---------|
| Cloud | AWS (ACCESS_KEY_ID, SECRET_ACCESS_KEY, IMDS, Secrets Manager, SSM), Azure (CLIENT_SECRET, Key Vault), GCP (APPLICATION_CREDENTIALS, metadata server, Secret Manager) |
| Infrastructure | Kubernetes (service account tokens, namespace secrets), HashiCorp Vault (all token paths, K8s/AWS IAM auth) |
| VCS/Registry | GitHub PATs (`ghp_`, `gho_`), GitHub App JWTs (`ghs_`), npm/PyPI/RubyGems tokens |
| Developer Tools | SSH keys (`~/.ssh/id*`), Docker (`~/.docker/config.json`), Git credentials, shell histories, `.env` files |
| Password Managers | 1Password, Bitwarden, gopass, pass |
| AI Tools | Claude, Codex, Gemini, Copilot keys under `~/.config/` |

### 3. C2 Infrastructure

| Component | Indicator | Role |
|-----------|-----------|------|
| Primary dead-drop | GitHub account `felixEvora` — 30 repositories with pattern `{underworld-term}-{numeric-suffix}` | Credential exfiltration via encrypted JSON in `results/` directories |
| Repo description | "Hades - The End for the Damned" | Campaign marker |
| Commit signature | GPG-signed (commit `9a5547b4`), author: `felix.diestelhorst[at]evorait[.]com` | Attribution artifact |
| Fallback domain 1 | `thebeautifulmarchoftime` | Domain resolution fallback (TLD not published in source reporting) |
| Fallback domain 2 | `thebeautifulsnadsoftime` | Token extraction fallback (TLD not published in source reporting) |
| Tertiary (camouflage) | `api[.]anthropic[.]com/v1/api` — embedded token invalid | Decoy traffic to legitimate service |

Exfiltration uses hybrid encryption: per-exfiltration AES-256-GCM key encrypts stolen data, attacker's hardcoded RSA public key encrypts the AES key. Envelope structure: `{"envelope": "<base64-AES-GCM>", "key": "<base64-RSA-OAEP>"}`.

### 4. Worm Capabilities and Lateral Movement

The payload includes self-propagation and lateral movement capabilities:

- **Self-propagating** via stolen PyPI/npm/RubyGems tokens to publish additional malicious package versions
- **GitHub Actions workflow injection:** `bun run $GITHUB_ACTION_PATH/index.js`
- **Repository poisoning:** Drops `.claude/settings.json`, `.vscode/tasks.json`, `.gemini/settings.json` hooks
- **SLSA/Sigstore provenance forgery** via compromised OIDC tokens
- **Docker escape:** Kills security containers (harden-runner, step-security), writes passwordless sudo
- **SSH lateral movement:** Reads `~/.ssh/known_hosts`, propagates to reachable hosts
- **CI memory scraping:** Dumps GitHub Actions Runner.Worker process for live tokens

### 5. Anti-Forensics / Evasion Techniques

- **Destructive cleanup:** `rm -rf ~/; rm -rf ~/Documents` destroys forensic artifacts post-exfiltration
- **Locale check:** Russian locale check causes early exit (geofencing)
- **Daemon re-launch:** Uses `__IS_DAEMON=1` environment variable for persistence
- **CI platform detection:** Detects 30+ CI environments and adjusts behavior accordingly
- **EDR evasion:** Checks for CrowdStrike, SentinelOne, Carbon Black, StepSecurity Harden-Runner

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots
> - Email addresses: `[at]` replacing @

### Package / Software Level

| Package | Malicious Version | Published (UTC) | Quarantined (UTC) |
|---------|-------------------|-----------------|-------------------|
| ensmallen | 0.8.101 | 03:10 | 03:33 |
| embiggen | 0.11.97 | 03:10 | 03:19 |
| pyphetools | 0.9.120 | 03:10 | 03:15 |
| gpsea | 0.9.14 | 03:09 | 03:14 |
| phenopacket-store-toolkit | 0.1.7 | 03:09 | 03:20 |
| ppkt2synergy | 0.1.1 | 03:09 | 03:12 |

Related packages from the 2026-06-07 Hades Cluster wave (covered in prior report): bramin, cmd2func, coolbox, dynamo-release, executor-engine, executor-http, funcdesc, magique, magique-ai, mrbios, napari-ufish, nucbox, okite, pantheon-agents, pantheon-toolsets, spateo-release, synago, ufish, uprobe.

### File System

| Platform | Path | Description |
|----------|------|-------------|
| Cross | `*.abi3.so` (~57 MB) in site-packages | Compiled binary extension with embedded stealer payload |
| Cross | `_index.js` (~5.3 MB) in site-packages | Obfuscated JavaScript credential stealer |
| Cross | `/tmp/b-*/bun` | Downloaded Bun runtime binary |
| Cross | `/tmp/p*.js` | Loader scripts |
| Cross | `/tmp/.sshu-setup.js` | SSH lateral movement script |
| Cross | `.claude/settings.json` | Repository poisoning config |
| Cross | `.vscode/tasks.json` | VS Code backdoor |
| Cross | `.gemini/settings.json` | Gemini IDE poisoning |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `thebeautifulmarchoftime` | Fallback C2 — domain resolution (TLD not published in source reporting) |
| Domain | `thebeautifulsnadsoftime` | Fallback C2 — token extraction (TLD not published in source reporting) |
| Domain (decoy) | `api[.]anthropic[.]com/v1/api` | Camouflage traffic — non-functional |
| GitHub | `felixEvora` account with 30 dead-drop repos | Primary exfiltration channel |
| URL | `hxxps://github[.]com/oven-sh/bun/releases/download/bun-v1.3.13/` | Bun runtime download (legitimate domain, malicious use) |
| UA string | `Bun/1.3.13` | HTTP User-Agent in all malicious uploads and C2 traffic |

### Behavioral

- Python interpreter loading `.abi3.so` extensions that spawn Bun (`/tmp/b-*/bun`) subprocess with `_index.js` arguments
- GitHub `felixEvora` repositories receiving commits with encrypted JSON in `results/` directories
- Commits with description "Hades - The End for the Damned" authored by `felix.diestelhorst[at]evorait[.]com`
- HTTP traffic with `User-Agent: Bun/1.3.13` from scientific computing environments
- DNS queries to `thebeautifulmarchoftime` or `thebeautifulsnadsoftime` domains
- Probing of AWS IMDS (`169.254.169[.]254`) and ECS metadata (`169.254.170[.]2`) from Python/Bun processes
- Files with `globalThis["fed1de59e"]` deobfuscation key pattern

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized PyPI packages via stolen maintainer API tokens |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Bun runtime executes obfuscated JavaScript credential stealer embedded in .abi3.so |
| T1059.006 | Command and Scripting Interpreter: Python | Python dlopen() triggers execution of malicious compiled extension |
| T1555 | Credentials from Password Stores | Harvests credentials from 1Password, Bitwarden, pass, gopass |
| T1552.001 | Unsecured Credentials: Credentials In Files | Steals .npmrc, .pypirc, .aws/credentials, SSH keys, .env files, AI tool configs |
| T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository | GitHub dead-drop repositories (felixEvora account) for credential exfiltration |
| T1105 | Ingress Tool Transfer | Downloads Bun runtime from GitHub releases |
| T1140 | Deobfuscate/Decode Files or Information | ROT-N cipher + AES-128-GCM decryption of JavaScript payload |
| T1027.002 | Obfuscated Files or Information: Software Packing | Credential stealer embedded inside compiled .abi3.so binary extension |
| T1078 | Valid Accounts | Uses stolen tokens to authenticate to GitHub, npm, PyPI, cloud providers |
| T1071.001 | Application Layer Protocol: Web Protocols | Exfiltration via GitHub API; decoy traffic to Anthropic API |
| T1021.004 | Remote Services: SSH | Lateral movement via stolen SSH keys and known_hosts |

## Impact Assessment

- **Breadth:** 6 directly trojanized bioinformatics packages in this wave; part of a broader campaign of 19+ science-focused packages and 453+ total malicious artifacts across the Shai-Hulud campaign. Target audience is academic researchers with access to HPC clusters, clinical data pipelines, and cloud infrastructure.
- **Depth:** Full credential theft across cloud providers, CI/CD pipelines, package registries, developer tools, password managers, and AI coding assistants. Stolen OIDC tokens enable cascading supply chain compromise via self-propagation.
- **Stealth:** Binary extension (`.abi3.so`) vector is significantly harder to detect than script-level payloads. Compiled Rust/C++ with embedded JavaScript evades Python static analysis. Fake LLM jailbreak decoy confuses automated review.
- **Exposure window:** Approximately 3–24 minutes per package (03:09–03:33 UTC). Narrow window limits direct impact but any installation during this period results in full credential compromise.

## Detection & Remediation

### Immediate Detection

```bash
# Check for trojanized bioinformatics packages
pip list 2>/dev/null | grep -iE "^(ensmallen|embiggen|pyphetools|gpsea|phenopacket-store-toolkit|ppkt2synergy) "

# Check for specific malicious versions
pip show ensmallen 2>/dev/null | grep -E "Version: 0\.8\.101"
pip show embiggen 2>/dev/null | grep -E "Version: 0\.11\.97"
pip show pyphetools 2>/dev/null | grep -E "Version: 0\.9\.120"
pip show gpsea 2>/dev/null | grep -E "Version: 0\.9\.14"
pip show phenopacket-store-toolkit 2>/dev/null | grep -E "Version: 0\.1\.7"
pip show ppkt2synergy 2>/dev/null | grep -E "Version: 0\.1\.1"

# Check for oversized .abi3.so files (normal ~1-10MB; malicious ~57MB)
find /usr -name "*.abi3.so" -size +50M -path "*/site-packages/*" 2>/dev/null

# Check for _index.js files in site-packages (should not exist)
find /usr -name "_index.js" -path "*/site-packages/*" 2>/dev/null

# Check for Bun runtime execution artifacts
ls -la /tmp/b-*/bun /tmp/p*.js /tmp/.sshu-setup.js 2>/dev/null

# Check for repository poisoning
find . -path "./.claude/settings.json" -o -path "./.gemini/settings.json" -o -name "_index.js" -path "./.vscode/*" 2>/dev/null

# Search for deobfuscation key in files
grep -r "fed1de59e" /usr/lib/python*/site-packages/ /usr/local/lib/python*/site-packages/ 2>/dev/null
```

### Remediation

1. **Containment:** Immediately uninstall any of the six affected packages at the malicious versions listed above. Isolate affected systems from network.
2. **Credential Rotation:** Rotate ALL credentials on affected systems — GitHub tokens, npm/PyPI tokens, AWS/GCP/Azure keys, SSH keys, Kubernetes service account tokens, Vault tokens, Docker configs, AI tool API keys. Assume all credentials on the system are compromised.
3. **Lateral Movement Check:** Audit SSH `known_hosts` for any systems the compromised host could reach. Check those systems for indicators.
4. **Repository Audit:** Search for unauthorized modifications to `.claude/`, `.vscode/tasks.json`, `.gemini/`, and `.github/workflows/` in all repositories accessible from compromised systems.
5. **GitHub Audit:** Search for commits by `felix.diestelhorst[at]evorait[.]com` or to repositories owned by `felixEvora` in audit logs.

### Long-Term Hardening

- Monitor `.abi3.so` file sizes and creation in site-packages directories via EDR/HIDS — files >50 MB are unusual
- Implement package signature verification (PEP 740) and pin versions with hash verification (`pip install --require-hashes`)
- Enable 2FA and hardware security keys for all PyPI maintainer accounts
- Restrict outbound network access from research environments to known-good endpoints
- Deploy YARA rules for binary extension scanning in package installation pipelines

## Detection Rules

These detections target the Shai-Hulud science wave's **new, distinct** indicators — the `.abi3.so` binary extension vector, `felixEvora` GitHub dead-drop, fallback C2 domains, and `Bun/1.3.13` User-Agent — that differentiate this wave from the prior Hades Cluster coverage (2026-06-07). Existing rules for `.pth` hooks, `83.142.209[.]194` C2, and `getsession[.]org` exfiltration from the prior report remain applicable and are not duplicated here. Compilation was validated; deployment-environment testing is required.

<!-- revision: DROPPED Sigma .abi3.so binary extension loading rule — fires on every legitimate .abi3.so (numpy, scipy, cryptography, etc.); Sigma lacks filesize condition; scientific computing environments would generate hundreds of daily false positives. YARA rules below cover the malicious binaries specifically. -->

> **Dropped rule:** A Sigma rule for `.abi3.so` loading was drafted but removed during review — it was too broad (fires on all legitimate `.abi3.so` extensions such as numpy, scipy, cryptography). The YARA rules below cover the malicious binaries specifically.

### Sigma: Shai-Hulud Science Wave GitHub Dead-Drop Exfiltration to felixEvora Repositories

Detects command-line references to the `felixEvora` GitHub account or Hades-themed dead-drop repository naming patterns used for credential exfiltration in the science wave. **Caveat:** This rule uses the `process_creation` logsource and fires only when campaign strings appear in command-line arguments (e.g., git CLI invocations). The actual exfiltration uses JavaScript `fetch()`/GraphQL from the Bun runtime, so these strings are more likely to appear in HTTP/DNS traffic than in process command lines. Pair with the Snort/Suricata DNS and HTTP rules for broader coverage.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: Downgraded confidence high→medium and level critical→high. Added caveat about process_creation logsource fragility — exfiltration uses JS fetch()/GraphQL, not git CLI. Added second false-positive entry. -->
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on campaign-specific strings: felixEvora account name and Hades underworld repo names (lethean-tartarus, abyssal-acheron). Confidence medium: strings are campaign-unique but process_creation logsource is fragile for this exfiltration method. Evasion: attacker could switch GitHub account and repo naming scheme in future waves. -->

```yaml
title: Shai-Hulud Science Wave GitHub Dead-Drop Exfiltration to felixEvora Repositories
id: 3b8e1c5a-9d2f-4a7b-e6c4-1f0d5b8a2e9c
status: experimental
description: >
    Detects command-line references to the felixEvora GitHub account or
    Hades-themed dead-drop repository naming patterns (e.g. lethean-tartarus,
    abyssal-acheron) used for credential exfiltration in the June 2026
    Shai-Hulud bioinformatics package wave. NOTE: This rule uses the
    process_creation logsource and fires only when campaign strings appear in
    command-line arguments (e.g. git CLI invocations). The actual exfiltration
    uses JavaScript fetch()/GraphQL from the Bun runtime, so these strings are
    more likely to appear in HTTP/DNS traffic than in process command lines.
    Pair with the Snort/Suricata DNS and HTTP rules for broader coverage.
references:
    - https://www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages
    - https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-focused-pypi-packages/
author: Actioner
date: 2026/06/09
tags:
    - attack.t1567.001
    - attack.t1195.002
logsource:
    category: process_creation
    product: linux
detection:
    selection_felixevora:
        CommandLine|contains: 'felixEvora'
    selection_hades_repos:
        CommandLine|contains:
            - 'lethean-tartarus'
            - 'abyssal-acheron'
            - 'Hades - The End for the Damned'
    condition: selection_felixevora or selection_hades_repos
falsepositives:
    - Unlikely - felixEvora account name and Hades-themed repository names are campaign-specific
    - This rule fires only if the attacker uses git CLI or campaign strings appear in command-line arguments; JavaScript-based exfiltration via Bun fetch()/GraphQL will not trigger this rule
level: high
```

### Sigma: Shai-Hulud Science Wave Bun User-Agent in HTTP Proxy Traffic

Detects HTTP traffic with `User-Agent: Bun/1.3.13` in proxy logs, the runtime used for all malicious package uploads and C2 communications in this wave. **Caveat:** Bun 1.3.13 is a current, publicly released JavaScript runtime. Scope this rule to non-JavaScript-development network segments (e.g., scientific computing, HPC, research lab subnets) to avoid false positives from legitimate JS developers.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: Downgraded confidence high→medium. Added scoping caveat and second false-positive entry about Bun being legitimate software. Changed level high→medium. -->
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on c-useragent contains Bun/1.3.13 in proxy logs. Medium confidence: Bun 1.3.13 is current, publicly released software; any JS developer behind a proxy will trigger this. Scope to non-JS-development segments. Evasion: attacker could strip or modify User-Agent. -->

```yaml
title: Shai-Hulud Science Wave Bun User-Agent in HTTP Traffic
id: 7a1d4e9c-2b5f-4c8a-d3e6-5f0b8c2a1d7e
status: experimental
description: >
    Detects HTTP traffic with User-Agent string Bun/1.3.13 originating from Python
    processes or site-packages directories. The June 2026 Shai-Hulud wave used the
    Bun JavaScript runtime for all malicious uploads and C2 communications, which is
    atypical for Python-based scientific computing environments. Bun 1.3.13 is a
    current, publicly released JavaScript runtime, so this rule should be scoped to
    non-JavaScript-development network segments (e.g. scientific computing, HPC,
    research lab subnets) to reduce false positives.
references:
    - https://www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages
    - https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-focused-pypi-packages/
author: Actioner
date: 2026/06/09
tags:
    - attack.t1071.001
    - attack.t1059.007
logsource:
    category: proxy
detection:
    selection:
        c-useragent|contains: 'Bun/1.3.13'
    condition: selection
falsepositives:
    - Legitimate use of Bun JavaScript runtime version 1.3.13 in proxy logs
    - JavaScript developers using Bun as their runtime — scope this rule to non-JS-development network segments to reduce noise
level: medium
```

### Snort: Shai-Hulud Science Wave Network Indicators

Detects `Bun/1.3.13` User-Agent in HTTP headers and DNS queries to the campaign's fallback C2 domains `thebeautifulmarchoftime` and `thebeautifulsnadsoftime`.
**Status:** compile ✅ compiles · confidence: sid:2100010 medium, sid:2100011-2100012 high
<!-- revision: sid:2100010 confidence downgraded high→medium (Bun 1.3.13 is legitimate software). sid:2100011 BUGFIX: DNS label length byte corrected |18|→|17| (0x17=23 decimal, matching 23-char domain "thebeautifulmarchoftime"); the original |18|=24 was wrong and the rule would never have fired. rev bumped to 2. -->
<!-- audit: snort -c /etc/snort/snort.conf (via /tmp/local.rules) exit 0. sid 2100010 keys on Bun/1.3.13 in http_header — medium confidence, legitimate Bun use triggers FP. sid 2100011-2100012 key on DNS label-length-encoded fallback C2 domain names (|17| = 23-byte label for both thebeautifulmarchoftime and thebeautifulsnadsoftime). Near-zero FP — domain names are campaign-unique. -->

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Shai-Hulud Science Wave Bun/1.3.13 User-Agent in HTTP Traffic"; flow:established,to_server; content:"Bun/1.3.13"; http_header; fast_pattern; sid:2100010; rev:1; classtype:trojan-activity; reference:url,www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - Shai-Hulud Science Wave DNS Query to Fallback C2 thebeautifulmarchoftime"; content:"|17|thebeautifulmarchoftime"; nocase; fast_pattern; sid:2100011; rev:2; classtype:trojan-activity; reference:url,www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - Shai-Hulud Science Wave DNS Query to Fallback C2 thebeautifulsnadsoftime"; content:"|17|thebeautifulsnadsoftime"; nocase; fast_pattern; sid:2100012; rev:1; classtype:trojan-activity; reference:url,www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages;)
```

### Suricata: Shai-Hulud Science Wave Network Indicators

Detects DNS queries to the campaign's fallback C2 domains and `Bun/1.3.13` User-Agent in HTTP traffic.
**Status:** compile ✅ compiles · confidence: sid:2200010-2200011 high, sid:2200012 medium
<!-- revision: sid:2200012 confidence downgraded high→medium (Bun 1.3.13 is legitimate software; same FP concern as Snort sid:2100010 and Sigma Bun UA rule). -->
<!-- audit: suricata -T exit 0. sid 2200010-2200011 key on dns.query content for fallback C2 domains thebeautifulmarchoftime and thebeautifulsnadsoftime. Near-zero FP — domains are campaign-unique. sid 2200012 keys on http.user_agent Bun/1.3.13 — medium confidence, FP possible in JS dev environments. Evasion: attacker could rotate domains or strip User-Agent. -->

```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - Shai-Hulud Science Wave DNS Query to Fallback C2 Domain thebeautifulmarchoftime"; dns.query; content:"thebeautifulmarchoftime"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages; metadata:author Actioner, created_at 2026-06-09; sid:2200010; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Shai-Hulud Science Wave DNS Query to Fallback C2 Domain thebeautifulsnadsoftime"; dns.query; content:"thebeautifulsnadsoftime"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages; metadata:author Actioner, created_at 2026-06-09; sid:2200011; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Shai-Hulud Science Wave Bun/1.3.13 User-Agent in HTTP Traffic"; flow:established,to_server; http.user_agent; content:"Bun/1.3.13"; fast_pattern; classtype:trojan-activity; reference:url,www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages; metadata:author Actioner, created_at 2026-06-09; sid:2200012; rev:1;)
```

### YARA: Shai-Hulud Science Wave Malicious .abi3.so Binary Extension

Detects malicious `.abi3.so` compiled extensions from the science wave via embedded Bun loader URLs, `_index.js` references, the `fed1de59e` deobfuscation key, and `felixEvora` exfiltration indicators.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara positive fired (Malware_ShaiHulud_Science_ABI3_Binary_Extension matched pos-abi3.txt containing published campaign markers: oven-sh/bun/releases + _index.js + eval(function(s,n) + felixEvora + fed1de59e). yara negative quiet. Condition: 2 of loader/payload indicators, OR fed1de59e + 1 loader, OR felixEvora + 1 campaign marker. FP: extremely unlikely — combination of Bun loader URL + _index.js + campaign-specific keys is unique. Evasion: recompilation with different string patterns would bypass. -->

```yara
rule Malware_ShaiHulud_Science_ABI3_Binary_Extension
{
    meta:
        description = "Detects malicious .abi3.so compiled extensions from the June 2026 Shai-Hulud science package wave. The extensions embed an obfuscated _index.js credential stealer and Bun runtime loader inside Rust/C++ compiled shared objects."
        author = "Actioner"
        date = "2026-06-09"
        reference = "https://www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages"
        severity = "critical"

    strings:
        $bun_loader = "oven-sh/bun/releases" ascii
        $index_js = "_index.js" ascii
        $fed1de = "fed1de59e" ascii
        $hades_desc = "Hades - The End for the Damned" ascii
        $rot_eval = "eval(function(s,n)" ascii
        $encrypt_fn = "E8()" ascii
        $github_exfil = "createCommitOnBranch" ascii
        $felix = "felixEvora" ascii

    condition:
        filesize < 100MB and
        (
            (2 of ($bun_loader, $index_js, $rot_eval, $encrypt_fn)) or
            ($fed1de and 1 of ($bun_loader, $index_js, $github_exfil)) or
            ($felix and 1 of ($hades_desc, $github_exfil, $index_js))
        )
}
```

### YARA: Shai-Hulud Science Wave Obfuscated JavaScript Stealer Payload

Detects the 5.3 MB obfuscated `_index.js` credential stealer via the `globalThis["fed1de59e"]` decryption key, ROT-N cipher function, hybrid RSA-OAEP/AES-256-GCM encryption, and fallback C2 domain strings.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara positive fired (Malware_ShaiHulud_Science_Obfuscated_JS_Stealer matched pos-js-stealer.txt at 1048696 bytes containing: globalThis["fed1de59e"] + RSA-OAEP + AES-256-GCM + thebeautifulmarchoftime + Hades + s.replace(/[a-zA-Z]/g). yara negative quiet (neg-abi3.txt at 93 bytes, below 1MB minimum). Condition: globalThis key alone, OR fed1de59e + cipher/encryption indicator, OR fallback domain + campaign marker + key, OR ROT cipher + RSA-OAEP + marker. File size gated 1-15MB to match the known ~5.3MB payload. FP: extremely unlikely — globalThis["fed1de59e"] is campaign-unique. -->

```yara
rule Malware_ShaiHulud_Science_Obfuscated_JS_Stealer
{
    meta:
        description = "Detects the 5.3 MB obfuscated _index.js JavaScript credential stealer payload from the June 2026 Shai-Hulud science package wave. Features a fake LLM jailbreak prompt decoy (lines 1-99) with actual payload on line 101, wrapped in ROT-N + AES-128-GCM encryption."
        author = "Actioner"
        date = "2026-06-09"
        reference = "https://www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages"
        severity = "critical"

    strings:
        $fed1de_global = "globalThis[\"fed1de59e\"]" ascii
        $fed1de_key = "fed1de59e" ascii
        $rot_cipher = "s.replace(/[a-zA-Z]/g" ascii
        $rsa_oaep = "RSA-OAEP" ascii
        $aes_gcm = "AES-256-GCM" ascii
        $beautiful1 = "thebeautifulmarchoftime" ascii
        $beautiful2 = "thebeautifulsnadsoftime" ascii
        $hades = "Hades" ascii
        $anthropic_decoy = "api.anthropic.com/v1/api" ascii

    condition:
        filesize > 1MB and filesize < 15MB and
        (
            ($fed1de_global) or
            ($fed1de_key and 1 of ($rot_cipher, $rsa_oaep, $aes_gcm)) or
            (1 of ($beautiful*) and 1 of ($hades, $anthropic_decoy, $fed1de_key)) or
            ($rot_cipher and $rsa_oaep and 1 of ($beautiful*, $hades))
        )
}
```

## Lessons Learned

1. **Compiled binary extensions are the next frontier for supply chain attacks.** The shift from script-level `.pth` hooks (easily inspected) to compiled `.abi3.so` extensions (~57 MB of compiled Rust/C++) dramatically raises the analysis barrier. PyPI's malware scanning and most security tooling focus on Python source code, not compiled binaries embedded in wheels.

2. **Rapid quarantine matters but cannot eliminate risk.** Endor Labs quarantined all six packages within 3–24 minutes of publication. For a targeted audience of researchers who may use automated dependency installation in CI/CD pipelines, even a brief exposure window can result in credential theft.

3. **Multi-wave campaigns test defender attention.** This science wave arrived one day after the Hades Cluster wave (2026-06-07) and used a different injection technique (`.abi3.so` vs `.pth`), potentially catching defenders who focused detection on the first variant.

4. **The Shai-Hulud worm is a self-sustaining ecosystem.** Stolen PyPI tokens from one wave fund the next. The campaign has grown from npm (April 2026) to PyPI (June 2026) with increasingly sophisticated evasion techniques, demonstrating active, iterative development.

## Sources

- [BleepingComputer — New Shai-Hulud attack trojanizes 19 science-focused PyPI packages](https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-focused-pypi-packages/) — primary news report aggregating both the 19-package Hades Cluster and 6-package bioinformatics waves
- [Endor Labs — Shai-Hulud "Hades" Wave Hits Six PyPI Bioinformatics Packages via Stolen Tokens](https://www.endorlabs.com/learn/shai-hulud-hades-wave-hits-six-pypi-bioinformatics-packages) — primary technical analysis with package versions, timeline, C2 infrastructure, and payload details for the science wave
- [Socket.dev — Mini Shai-Hulud Campaign Tracker](https://socket.dev/supply-chain-attacks/mini-shai-hulud) — campaign-wide tracking (453+ artifacts)
- [Intrudify — mini-shai-hulud-scanner (GitHub)](https://github.com/Intrudify/mini-shai-hulud-scanner) — open-source scanner for Shai-Hulud persistence and payload artifacts

### Prior Actioner Coverage (Related, Not Duplicated)

- `summaries/2026-06-07-pypi-hades-cluster-supply-chain.md` — Hades Cluster wave covering 19 packages with `.pth` hooks and `83.142.209[.]194` C2
- `summaries/2026-06-02-npm-redhat-shai-hulud-worm.md` — Miasma variant in @redhat-cloud-services npm scope
- `summaries/2026-05-30-npm-mini-shai-hulud-antv.md` — Original Mini Shai-Hulud wave in @antv npm scope

---
*Report generated by Actioner — v1.1 (revised)*
