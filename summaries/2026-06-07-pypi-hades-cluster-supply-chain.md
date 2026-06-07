# Technical Analysis Report: Hades Cluster PyPI Supply Chain Attack (2026-06-07)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-07
Version: 1.1

## Executive Summary

On June 7, 2026, Socket disclosed a coordinated PyPI supply-chain attack dubbed the "Hades Cluster" — a new wave of the Shai-Hulud / Miasma worm lineage operated by TeamPCP. The attack compromised 19 legitimate PyPI packages (37 malicious wheel artifacts) targeting bioinformatics and deep-learning researchers. The compromised releases inject a `*-setup.pth` startup hook that executes automatically during Python interpreter initialization — no explicit import required. The hook downloads the Bun JavaScript runtime (v1.3.13) from GitHub and executes an obfuscated ~11 MB credential stealer (`_index.js` / `router_runtime.js`) that harvests tokens from GitHub, npm, PyPI, AWS, GCP, Azure, Kubernetes, HashiCorp Vault, SSH keys, Docker configs, password managers, and shell histories. Stolen credentials are exfiltrated via GitHub GraphQL dead-drop repositories (marked "Hades - The End for the Damned") and encrypted uploads to Session/Oxen infrastructure. The campaign includes a destructive dead-man switch that executes `rm -rf ~/` if the stolen GitHub token is revoked, and geofenced destructive payloads targeting systems with Israeli or Iranian locales.

## Background: PyPI and Python Startup Hooks

PyPI is the primary package repository for the Python ecosystem, serving over 500,000 packages to millions of developers. Python's `.pth` file mechanism is a rarely discussed but powerful feature: any `.pth` file placed in a `site-packages` directory whose lines begin with `import` will be executed automatically by the Python interpreter during initialization — before any user code runs. This makes `.pth` files an ideal persistence and initial-execution vector for supply chain attacks, as the malicious code runs silently on every Python invocation after the compromised package is installed, regardless of whether the package is explicitly imported.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-04-29 | Mini Shai-Hulud campaign begins targeting npm ecosystem |
| 2026-04-30 | PyTorch Lightning (`lightning` 2.6.2, 2.6.3) compromised via same TTP |
| 2026-05-11 | TeamPCP publishes 400+ malicious versions across npm/PyPI in 5 hours |
| 2026-06-07 | Socket detects "Hades Cluster" wave: 37 malicious wheels across 19 PyPI packages |
| 2026-06-07 | Security Online publishes advisory; packages flagged for removal |

## Root Cause: Maintainer Account Takeover

The attack compromised legitimate PyPI maintainer accounts (method not yet fully disclosed) and published trojanized wheel files to 19 existing packages with established user bases in the bioinformatics and deep-learning communities. The hijacked accounts allowed the attacker to publish new versions of trusted packages, bypassing typical typosquatting detection.

## Technical Analysis of the Malicious Payload

### 1. Stage 1: .pth Startup Hook Injection

The compromised wheel files include a `*-setup.pth` file placed in `site-packages`. When the Python interpreter starts, it processes `.pth` files automatically. Lines beginning with `import` are executed as Python code during initialization. The `.pth` hook:

1. Checks for a marker file (`/tmp/.bun_ran`) to avoid re-execution
2. Downloads the Bun JavaScript runtime (v1.3.13) from `github.com/oven-sh/bun/releases/download/bun-v1.3.13/` to `/tmp/b.zip`
3. Extracts to `/tmp/b/bun`
4. Executes the obfuscated JavaScript payload

### 2. Stage 2: Obfuscated JavaScript Credential Stealer

The payload (`_index.js` or `router_runtime.js`, ~11 MB) uses multiple obfuscation layers:

- **String array rotation** consistent with `javascript-obfuscator`
- **`__decodeScrambled()` cipher function** using PBKDF2-SHA256 with salt `ctf-scramble-v2` (200,000 iterations)
- **AES-256-GCM encrypted stages** with per-string IVs
- **Secondary encryption layer** using salt `svksjrhjkcejg` (200,000 PBKDF2 iterations)

The stealer harvests credentials from:

| Category | Targets |
|----------|---------|
| VCS/CI Tokens | GitHub PATs (`ghp_`, `gho_`), GitHub App JWTs (`ghs_`), OIDC tokens, `ACTIONS_ID_TOKEN_REQUEST_TOKEN` |
| Package Registry | `.npmrc`, `.pypirc`, RubyGems credentials |
| Cloud Providers | AWS (IMDS `169.254.169.254`, ECS `169.254.170.2`, `~/.aws/credentials`), GCP, Azure CLI tokens |
| Infrastructure | Kubernetes (`~/.kube/config`, in-cluster service account tokens), HashiCorp Vault, Terraform state |
| Developer Tools | SSH private keys, Docker `config.json`, Git credentials, shell histories, `.env` files |
| Password Managers | 1Password (op CLI), Bitwarden, pass, gopass |
| CI Platforms | Detects 20+ CI environments via env vars (`GITHUB_ACTIONS`, `CIRCLECI`, `CODEBUILD_BUILD_ID`, `VERCEL`, etc.) |

### 3. C2 Infrastructure

| Component | Indicator | Role |
|-----------|-----------|------|
| Primary C2 | `83.142.209[.]194` | Payload download, stage retrieval, exfiltration |
| Payload URL | `hxxps://83.142.209[.]194/transformers.pyz` | Second-stage PyPI payload |
| Stage Retrieval | `hxxps://83.142.209[.]194/v1/models` | Config/model retrieval endpoint |
| Exfiltration | `hxxps://83.142.209[.]194/v1/weights` | Credential upload endpoint |
| Destructive | `hxxps://83.142.209[.]194/audio.mp3` | Destructive stage media trigger |
| Encrypted Upload | `hxxp://filev2[.]getsession[.]org/file/` | Session/Oxen encrypted upload |
| Seed Nodes | `seed1[.]getsession[.]org`, `seed2[.]getsession[.]org`, `seed3[.]getsession[.]org` | Oxen network nodes |
| Decoy | `api[.]anthropic[.]com/v1/api` | Camouflaged decoy traffic to Anthropic AI |
| Campaign Infra | `git-tanstack[.]com`, `api[.]masscan[.]cloud` | Campaign support infrastructure |
| Onion | `hxxp://22evxpggnkyrxpluewqsrv5j4jtde6hut2peq3w44d6ase676qlkoead[.]onion` | Tor-based extortion/leak site |

GitHub is used as a primary exfiltration channel via GraphQL `createCommitOnBranch` mutations to dead-drop repositories with the description "Hades - The End for the Damned". Commits are authored as `claude <claude@users.noreply.github.com>` to impersonate the Claude AI coding assistant.

### 4. Platform-Specific Behavior

#### Linux
- Persistence via systemd user service: `~/.config/systemd/user/gh-token-monitor.service`
- Dead-man switch script: `~/.local/bin/gh-token-monitor.sh`
- Config directory: `~/.config/gh-token-monitor/`
- PyPI second-stage persistence: `~/.local/bin/pgmonitor.py` with `pgsql-monitor.service`

#### macOS
- Persistence via LaunchAgent: `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`
- Shared script/config paths with Linux variant

### 5. Anti-Forensics / Evasion Techniques

- **Dead-man switch:** Polls `hxxps://api[.]github[.]com/user` every 60 seconds; executes `rm -rf ~/` if the stolen token is revoked (40x HTTP response)
- **Geofenced destruction:** Probabilistic `rm -rf /*` on systems with Israeli (`he_IL`, `Jerusalem`, `Tel_Aviv`) or Iranian (`fa_IR`, `Tehran`) locales/timezones
- **Claude impersonation:** Commits authored as `claude@users.noreply.github.com` to blend with legitimate AI coding assistant activity
- **Repository poisoning:** Drops `.claude/router_runtime.js`, `.claude/settings.json`, `.claude/setup.mjs`, `.vscode/tasks.json`, `.github/workflows/format-check.yml` into victim repos for lateral propagation
- **Decoy traffic:** Sends requests to `api.anthropic.com/v1/api` to disguise C2 communications among legitimate AI API calls

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots
> - IP addresses: `[.]` replacing dots

### Package / Software Level

| Package / Component | Malicious Versions | Description |
|---------------------|-------------------|-------------|
| bramin | Compromised wheel | Trojanized with .pth startup hook |
| cmd2func | Compromised wheel | Trojanized with .pth startup hook |
| coolbox | Compromised wheel | Trojanized with .pth startup hook |
| dynamo-release | Compromised wheel | Trojanized with .pth startup hook |
| executor-engine | Compromised wheel | Trojanized with .pth startup hook |
| executor-http | Compromised wheel | Trojanized with .pth startup hook |
| funcdesc | Compromised wheel | Trojanized with .pth startup hook |
| magique | Compromised wheel | Trojanized with .pth startup hook |
| magique-ai | Compromised wheel | Trojanized with .pth startup hook |
| mrbios | Compromised wheel | Trojanized with .pth startup hook |
| napari-ufish | Compromised wheel | Trojanized with .pth startup hook |
| nucbox | Compromised wheel | Trojanized with .pth startup hook |
| okite | Compromised wheel | Trojanized with .pth startup hook |
| pantheon-agents | Compromised wheel | Trojanized with .pth startup hook |
| pantheon-toolsets | Compromised wheel | Trojanized with .pth startup hook |
| spateo-release | Compromised wheel | Trojanized with .pth startup hook |
| synago | Compromised wheel | Trojanized with .pth startup hook |
| ufish | Compromised wheel | Trojanized with .pth startup hook |
| uprobe | Compromised wheel | Trojanized with .pth startup hook |

Related compromised packages from earlier Shai-Hulud waves: `lightning` (2.6.2, 2.6.3), `mistralai` (2.4.6), `guardrails-ai` (0.10.1).

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Cross | `*-setup.pth` in site-packages | c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c | Malicious .pth startup hook |
| Cross | `_runtime/router_runtime.js` | 5f5852b5f604369945118937b058e49064612ac69826e0adadca39a357dfb5b1 | Obfuscated JS credential stealer (~11 MB) |
| Cross | `_runtime/start.py` | 8046a11187c135da6959862ff3846e99ad15462d2ec8a2f77a30ad53ebd5dcf2 | Bun runtime downloader |
| Cross | `_index.js` | dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe | Alternative stealer payload name |
| Cross | `/tmp/b.zip`, `/tmp/b/bun` | — | Downloaded Bun runtime |
| Cross | `/tmp/.bun_ran` | — | Execution marker file |
| Cross | `/tmp/transformers.pyz` | — | PyPI second-stage payload |
| Linux | `~/.config/systemd/user/gh-token-monitor.service` | — | Dead-man switch persistence |
| Linux | `~/.local/bin/gh-token-monitor.sh` | — | Dead-man switch script |
| Linux | `~/.local/bin/pgmonitor.py` | — | PyPI second-stage persistence |
| Linux | `~/.config/systemd/user/pgsql-monitor.service` | — | PyPI persistence service |
| macOS | `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` | — | macOS LaunchAgent persistence |
| Cross | `.claude/router_runtime.js` | — | Repo poisoning payload |
| Cross | `.claude/settings.json` | — | Repo poisoning config |
| Cross | `.claude/setup.mjs` | — | Repo poisoning setup |
| Cross | `.vscode/tasks.json` | — | VS Code backdoor |
| Cross | `.github/workflows/format-check.yml` | — | GitHub Actions worm propagation |

Additional hashes from related Shai-Hulud waves:
- `56070a9d8de0c0ffb1ec5c309953cf4679432df5a78df9aeb020fbb73d2be9fb` (lightning 2.6.3 wheel)
- `2a314ea8be337e1ca9ec833ed13ed854d9fd38bce0a519cf288f3bec8d9e6f30` (PyPI init file stealer)
- `5245eb032e336b85cff0dbb3450d591826bf2ef214fd30d7eba1a763664e151b` (updated PyPI payload)

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `83.142.209[.]194` | Primary C2 — payload download, exfiltration |
| URL | `hxxps://83.142.209[.]194/transformers.pyz` | Second-stage payload download |
| URL | `hxxps://83.142.209[.]194/v1/models` | Stage retrieval endpoint |
| URL | `hxxps://83.142.209[.]194/v1/weights` | Credential exfiltration endpoint |
| Domain | `filev2[.]getsession[.]org` | Session/Oxen encrypted upload |
| Domain | `seed1[.]getsession[.]org` | Oxen seed node |
| Domain | `seed2[.]getsession[.]org` | Oxen seed node |
| Domain | `seed3[.]getsession[.]org` | Oxen seed node |
| Domain | `git-tanstack[.]com` | Campaign infrastructure |
| Domain | `api[.]masscan[.]cloud` | Campaign infrastructure |
| Domain (onion) | `22evxpggnkyrxpluewqsrv5j4jtde6hut2peq3w44d6ase676qlkoead[.]onion` | Tor leak site |
| URL | `hxxps://github[.]com/oven-sh/bun/releases/download/bun-v1.3.13/` | Bun runtime download (legitimate domain, malicious use) |

### Behavioral

- Python interpreter spawning Bun (`/tmp/b/bun`) subprocess with `_index.js` or `router_runtime.js` arguments
- GitHub GraphQL `createCommitOnBranch` mutations from development machines (not via `git push`)
- Commits authored as `claude <claude@users.noreply.github.com>` in repositories the developer did not intend to modify
- Dead-drop repositories with description "Hades - The End for the Damned" or "A Mini Shai-Hulud has Appeared"
- Commit messages prefixed with `OhNoWhatsGoingOnWithGitHub:`
- Commit keyword `FIRESCALE` used for fallback C2 discovery
- HTTP polling of `api.github.com/user` every 60 seconds from non-git processes
- Probing of AWS IMDS (`169.254.169.254`) and ECS metadata (`169.254.170.2`) from Python/Bun processes

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Trojanized PyPI packages via maintainer account takeover |
| T1546.016 | Event Triggered Execution: Installer Packages | `.pth` startup hook executes on every Python interpreter launch |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Bun runtime executes obfuscated JavaScript credential stealer |
| T1059.006 | Command and Scripting Interpreter: Python | `.pth` hook uses Python `import` to launch initial execution |
| T1555 | Credentials from Password Stores | Harvests credentials from 1Password, Bitwarden, pass, gopass |
| T1552.001 | Unsecured Credentials: Credentials In Files | Steals `.npmrc`, `.pypirc`, `.aws/credentials`, SSH keys, `.env` files |
| T1543.002 | Create or Modify System Process: Systemd Service | Persistence via `gh-token-monitor.service` and `pgsql-monitor.service` |
| T1543.004 | Create or Modify System Process: Launch Agent | macOS persistence via `com.user.gh-token-monitor.plist` |
| T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository | GitHub GraphQL dead-drop repositories for credential exfiltration |
| T1105 | Ingress Tool Transfer | Downloads Bun runtime from GitHub releases |
| T1140 | Deobfuscate/Decode Files or Information | Multi-layer obfuscation with PBKDF2/AES-GCM decryption |
| T1485 | Data Destruction | Dead-man switch `rm -rf ~/` on token revocation; geofenced `rm -rf /*` |
| T1078 | Valid Accounts | Uses stolen tokens to authenticate to GitHub, npm, cloud providers |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 over HTTPS to `83.142.209[.]194`; exfiltration via GitHub API |

## Impact Assessment

- **Breadth:** 19 compromised PyPI packages with combined hundreds of thousands of downloads; bioinformatics and deep-learning research communities primarily affected. Related Shai-Hulud waves have compromised 500+ packages across npm, PyPI, and Composer.
- **Depth:** Full credential theft across cloud providers, CI/CD pipelines, package registries, and developer tools — enabling cascading supply chain compromise. Stolen OIDC tokens allow the worm to propagate by publishing additional malicious package versions.
- **Stealth:** The `.pth` startup hook runs on every Python invocation without import, making it persistent and difficult to detect without filesystem inspection. Decoy traffic to Anthropic AI blends with legitimate developer activity.
- **Destructive potential:** Dead-man switch (`rm -rf ~/`) and geofenced destructive payloads represent unusual and aggressive anti-response capabilities.

## Detection & Remediation

### Immediate Detection

```bash
# Check for malicious .pth startup hooks
find /usr -name "*-setup.pth" -path "*/site-packages/*" 2>/dev/null

# Check for Bun execution markers
ls -la /tmp/.bun_ran /tmp/b.zip /tmp/b/bun 2>/dev/null

# Check for persistence services
ls -la ~/.config/systemd/user/gh-token-monitor.service ~/.config/systemd/user/pgsql-monitor.service 2>/dev/null
ls -la ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null

# Check for repository poisoning artifacts
find . -path "./.claude/router_runtime.js" -o -path "./.claude/setup.mjs" 2>/dev/null

# Check installed packages against known-compromised list
pip list 2>/dev/null | grep -iE "^(bramin|cmd2func|coolbox|dynamo-release|executor-engine|executor-http|funcdesc|magique|magique-ai|mrbios|napari-ufish|nucbox|okite|pantheon-agents|pantheon-toolsets|spateo-release|synago|ufish|uprobe) "

# Check for compromised lightning version
pip show lightning 2>/dev/null | grep -E "Version: 2\.6\.[23]"
```

### Remediation

1. **Containment:** Immediately uninstall any of the 19 compromised packages and `lightning` 2.6.2/2.6.3. Isolate affected systems from network.
2. **Credential Rotation:** Rotate ALL credentials on affected systems — GitHub tokens, npm tokens, PyPI tokens, AWS/GCP/Azure keys, SSH keys, Kubernetes service account tokens, Vault tokens. Assume all credentials on the system are compromised.
3. **Persistence Removal:** Delete `gh-token-monitor.service`, `pgsql-monitor.service`, `com.user.gh-token-monitor.plist`, and associated scripts. Check for `.claude/`, `.vscode/tasks.json`, and `.github/workflows/format-check.yml` modifications in all repositories.
4. **Audit GitHub Activity:** Search for unauthorized repositories, commits by `claude@users.noreply.github.com`, and GraphQL mutations in audit logs.
5. **Package Verification:** Pin package versions and verify checksums. Use `pip install --require-hashes` for critical dependencies.

### Long-Term Hardening

- Enable 2FA and hardware security keys for all PyPI maintainer accounts
- Implement package signature verification (PEP 740)
- Monitor `.pth` file creation in site-packages directories via EDR/HIDS
- Restrict outbound network access from development environments to known-good endpoints
- Audit CI/CD pipeline permissions and implement least-privilege OIDC token scoping

## Detection Rules

These detections target the Hades Cluster / Shai-Hulud credential stealer campaign at PoC/advisory-specific altitude. Four Sigma rules cover host-based indicators (file creation, process execution, persistence, exfiltration); Snort and Suricata rules cover C2 network traffic to `83.142.209[.]194` and exfiltration domains; two YARA rules match the obfuscated JavaScript stealer payload and the malicious `.pth` startup hook. All rules compile cleanly; compiles does not equal fires — verify against your telemetry.

### Sigma: Suspicious Python .pth Startup Hook File Creation

Detects creation of `*-setup.pth` files in Python site-packages directories, the initial execution mechanism of the Hades Cluster campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on TargetFilename endswith -setup.pth within site-packages. FP: legitimate .pth files exist but rarely end in -setup.pth. Evasion: attacker could rename the .pth suffix pattern. -->

```yaml
title: Suspicious Python .pth Startup Hook File Creation
id: 8e3a1d4f-7b2c-4e9a-b5d6-1f0c8a9e3d7b
status: experimental
description: >
    Detects creation of .pth files in Python site-packages directories, consistent with
    the Hades Cluster / Shai-Hulud supply chain attack that uses *-setup.pth startup hooks
    to execute credential-stealing payloads during Python interpreter initialization.
references:
    - https://securityonline.info/pypi-supply-chain-attack/
    - https://www.hendryadrian.com/shai-hulud-descends-to-hades-miasma-worm-campaign-spreads-with-new-pypi-wave/
    - https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/
author: Actioner
date: 2026/06/07
tags:
    - attack.t1546.016
    - attack.t1195.001
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains: 'site-packages'
        TargetFilename|endswith: '-setup.pth'
    condition: selection
falsepositives:
    - Legitimate Python packages using .pth files for path configuration
level: high
```

### Sigma: Bun Runtime Spawned by Python Process

Detects Python spawning the Bun JavaScript runtime with stealer payload arguments (`_index.js` / `router_runtime.js`), the core execution chain of the campaign.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on ParentImage=python* + Image=bun + CommandLine contains payload names. Highly specific — requires both Python parent and Bun child with campaign-specific JS filenames. Evasion: renaming the JS payload would bypass CommandLine match. -->

```yaml
title: Bun Runtime Spawned by Python Process
id: 2f4b8c6a-9d1e-4a3f-b7c5-0e2d6f8a1b4c
status: experimental
description: >
    Detects the Bun JavaScript runtime being spawned as a child of a Python process,
    a key behavior of the Hades Cluster credential stealer that downloads Bun v1.3.13
    to execute an obfuscated JavaScript payload (_index.js / router_runtime.js).
references:
    - https://securityonline.info/pypi-supply-chain-attack/
    - https://www.hendryadrian.com/shai-hulud-descends-to-hades-miasma-worm-campaign-spreads-with-new-pypi-wave/
    - https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/
author: Actioner
date: 2026/06/07
tags:
    - attack.t1059.007
    - attack.t1195.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith:
            - '/python'
            - '/python3'
            - '/python3.10'
            - '/python3.11'
            - '/python3.12'
            - '/python3.13'
        Image|endswith: '/bun'
        CommandLine|contains:
            - '_index.js'
            - 'router_runtime.js'
    condition: selection
falsepositives:
    - Developers intentionally using Bun from Python build scripts
level: critical
```

### Sigma: Hades Cluster Persistence via Systemd User Service

Detects creation of `gh-token-monitor.service` or `pgsql-monitor.service` in systemd user directories, the dead-man switch persistence mechanism.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Keys on campaign-specific service unit names. Near-zero FP — service names are unique to this campaign. Evasion: attacker could rename services in future variants. -->

```yaml
title: Hades Cluster Credential Stealer Persistence via Systemd User Service
id: 4c7e9a2b-1d5f-4b8c-a3e6-0f9d2c8b5a1e
status: experimental
description: >
    Detects creation of systemd user services used by the Hades Cluster / Shai-Hulud
    credential stealer for persistence, specifically gh-token-monitor.service and
    pgsql-monitor.service which implement a dead-man switch polling GitHub API.
references:
    - https://securityonline.info/pypi-supply-chain-attack/
    - https://research.jfrog.com/post/shai-hulud-here-we-go-again/
    - https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/
author: Actioner
date: 2026/06/07
tags:
    - attack.t1543.002
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains: '.config/systemd/user/'
        TargetFilename|endswith:
            - 'gh-token-monitor.service'
            - 'pgsql-monitor.service'
    condition: selection
falsepositives:
    - Unlikely - these service names are specific to this campaign
level: critical
```

### Sigma: GitHub API DNS Query from Bun/Python Process

Detects DNS resolution of `api.github.com` from Bun or Python processes, which may indicate the stealer's exfiltration or dead-man switch polling activity. High FP in development environments; use as a hunt/correlation signal alongside other Hades indicators, not standalone.
**Status:** compile ✅ compiles · confidence: low
<!-- audit: sigma check 0; splunk 0; log_scale 0. Broader than other rules — api.github.com is queried legitimately by dev tools. Confidence downgraded from medium to low per review: any Python/Bun developer querying GitHub API trips this; effectively behavioral/TTP altitude, not specific. Value is in correlation with other Hades indicators, not standalone. FP: any Python/Bun tool using GitHub API. -->

```yaml
title: GitHub API DNS Query from Bun or Python Process
id: 6a8d2e4f-3b1c-4f7a-9d5e-2c0b8a6f1d3e
status: experimental
description: >
    Detects DNS queries to api.github.com from Bun or Python processes.
    The Hades Cluster stealer polls this endpoint for dead-man switch checks
    and exfiltrates credentials via GraphQL mutations, but any developer
    tool using the GitHub API will also trigger this rule.
references:
    - https://securityonline.info/pypi-supply-chain-attack/
    - https://www.hendryadrian.com/shai-hulud-descends-to-hades-miasma-worm-campaign-spreads-with-new-pypi-wave/
    - https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/
author: Actioner
date: 2026/06/07
tags:
    - attack.t1567.001
logsource:
    category: dns_query
detection:
    selection_domain:
        QueryName: 'api.github.com'
    selection_process:
        Image|endswith:
            - '/bun'
            - '/python'
            - '/python3'
    condition: selection_domain and selection_process
falsepositives:
    - Legitimate developer tools querying GitHub API
    - CI/CD pipelines interacting with GitHub
    - Any Python or Bun application using GitHub REST or GraphQL API
level: low
```

### Snort: Hades Cluster C2 Communication

Detects traffic to the primary C2 IP `83.142.209[.]194` and the campaign-specific `/transformers.pyz` payload download URI.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /etc/snort/snort.conf -R exit 0. Rule 2100001 keys on destination IP (hardcoded C2). Rule 2100002 keys on specific URI path /transformers.pyz in http_uri. FP: unlikely — IP is dedicated C2 infrastructure. Evasion: C2 IP rotation. -->

```snort
alert tcp $HOME_NET any -> 83.142.209.194 any (msg:"Actioner - Hades Cluster C2 Communication to Known IP 83.142.209.194"; flow:established,to_server; sid:2100001; rev:1; classtype:trojan-activity; reference:url,research.jfrog.com/post/shai-hulud-here-we-go-again/;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - Hades Cluster PyPI Payload Download from C2 /transformers.pyz"; flow:established,to_server; content:"/transformers.pyz"; http_uri; fast_pattern; sid:2100002; rev:1; classtype:trojan-activity; reference:url,research.jfrog.com/post/shai-hulud-here-we-go-again/;)
```

### Suricata: Hades Cluster C2 and Exfiltration

Detects C2 communication to `83.142.209[.]194` (including `/v1/models` stage retrieval and `/v1/weights` exfiltration endpoints) and DNS queries to the Session/Oxen exfiltration domain `getsession[.]org`. Note: sid 2200004 (`getsession[.]org`) is confidence medium -- getsession.org is a legitimate messaging service; whitelist if Session is sanctioned in your environment.
**Status:** compile ✅ compiles · confidence: high (sid 2200001-2200003), medium (sid 2200004)
<!-- audit: suricata -T exit 0. sid 2200001 keys on dest IP. sid 2200002-2200003 key on URI path + host for specific C2 endpoints. sid 2200004 keys on DNS query to getsession.org exfil domain. Confidence for 2200004 broken out as medium per review: getsession.org is a legitimate messaging service (Session by Oxen); rule will FP in orgs that use Session. Requires environment-specific tuning — whitelist if Session is sanctioned. -->

```suricata
alert ip $HOME_NET any -> 83.142.209.194 any (msg:"Actioner - Hades Cluster C2 Communication to Known IP 83.142.209.194"; flow:to_server; classtype:trojan-activity; reference:url,research.jfrog.com/post/shai-hulud-here-we-go-again/; metadata:author Actioner, created_at 2026-06-07; sid:2200001; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Hades Cluster PyPI Second-Stage Retrieval /v1/models Endpoint"; flow:established,to_server; http.uri; content:"/v1/models"; fast_pattern; http.host; content:"83.142.209.194"; classtype:trojan-activity; reference:url,research.jfrog.com/post/shai-hulud-here-we-go-again/; metadata:author Actioner, created_at 2026-06-07; sid:2200002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Hades Cluster Credential Exfiltration /v1/weights Endpoint"; flow:established,to_server; http.uri; content:"/v1/weights"; fast_pattern; http.host; content:"83.142.209.194"; classtype:trojan-activity; reference:url,research.jfrog.com/post/shai-hulud-here-we-go-again/; metadata:author Actioner, created_at 2026-06-07; sid:2200003; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Hades Cluster DNS Query to Exfiltration Domain getsession.org"; dns.query; content:"getsession.org"; nocase; endswith; classtype:trojan-activity; reference:url,research.jfrog.com/post/shai-hulud-here-we-go-again/; metadata:author Actioner, created_at 2026-06-07; sid:2200004; rev:1;)
```

### YARA: Hades Cluster Credential Stealer Payload

Detects the obfuscated JavaScript credential stealer payload via campaign marker strings (`Hades`, `Shai-Hulud`, `FIRESCALE`), cipher function identifiers (`__decodeScrambled`, `ctf-scramble-v2`), and credential harvesting regex patterns.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara positive fired (Malware_HadesCluster_ShaiHulud_Credential_Stealer matched pos-stealer.txt containing published campaign markers + cipher identifiers). yara negative quiet. Condition: 2 markers, OR 1 cipher + 1 cred indicator, OR 1 marker + 1 regex + 1 cred. Covers both _index.js and router_runtime.js variants. FP: extremely unlikely — markers and cipher salts are campaign-unique. -->

```yara
rule Malware_HadesCluster_ShaiHulud_Credential_Stealer
{
    meta:
        description = "Detects the Hades Cluster / Shai-Hulud obfuscated JavaScript credential stealer payload (_index.js / router_runtime.js)"
        author = "Actioner"
        date = "2026-06-07"
        reference = "https://www.hendryadrian.com/shai-hulud-descends-to-hades-miasma-worm-campaign-spreads-with-new-pypi-wave/"
        hash = "5f5852b5f604369945118937b058e49064612ac69826e0adadca39a357dfb5b1"
        severity = "critical"

    strings:
        $marker1 = "Hades" ascii wide
        $marker2 = "The End for the Damned" ascii wide
        $marker3 = "Mini Shai-Hulud" ascii wide
        $marker4 = "IfYouYankThisToken" ascii wide
        $marker5 = "FIRESCALE" ascii wide
        $marker6 = "OhNoWhatsGoingOnWithGitHub" ascii wide

        $cred1 = "gh-token-monitor" ascii
        $cred2 = "pgsql-monitor" ascii
        $cred3 = ".npmrc" ascii
        $cred4 = ".pypirc" ascii

        $cipher1 = "__decodeScrambled" ascii
        $cipher2 = "ctf-scramble-v2" ascii
        $cipher3 = "svksjrhjkcejg" ascii

        $regex1 = "gh[op]_[A-Za-z0-9]{36,}" ascii
        $regex2 = "npm_[A-Za-z0-9]{36,}" ascii

    condition:
        filesize < 15MB and
        (
            (2 of ($marker*)) or
            (1 of ($cipher*) and 1 of ($cred*)) or
            (1 of ($marker*) and 1 of ($regex*) and 1 of ($cred*))
        )
}
```

### YARA: Hades Cluster Malicious .pth Startup Hook

Detects malicious Python `.pth` files that download the Bun runtime, matching the specific file paths (`/tmp/b.zip`, `/tmp/.bun_ran`) and download patterns used by the campaign.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara positive fired (Supply_Chain_HadesCluster_PTH_Startup_Hook matched pos-pth.txt containing published .pth content with oven-sh/bun URL + /tmp/b.zip + /tmp/.bun_ran). yara negative quiet. Condition: starts with "import " (as .pth spec requires) + 2 of 5 campaign-specific paths/artifacts. FP: extremely unlikely — combination of import-at-offset-0 + Bun download + /tmp markers is campaign-unique. -->

```yara
rule Supply_Chain_HadesCluster_PTH_Startup_Hook
{
    meta:
        description = "Detects malicious Python .pth startup hook files used by the Hades Cluster campaign to execute payloads during Python initialization"
        author = "Actioner"
        date = "2026-06-07"
        reference = "https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/"
        hash = "8046a11187c135da6959862ff3846e99ad15462d2ec8a2f77a30ad53ebd5dcf2"
        severity = "critical"

    strings:
        $pth_import = "import " ascii
        $bun_download = "oven-sh/bun/releases" ascii
        $bun_zip = "/tmp/b.zip" ascii
        $bun_ran = "/tmp/.bun_ran" ascii
        $start_py = "start.py" ascii
        $runtime_dir = "_runtime" ascii

    condition:
        filesize < 100KB and
        $pth_import at 0 and
        (2 of ($bun_download, $bun_zip, $bun_ran, $start_py, $runtime_dir))
}
```

## Lessons Learned

1. **Python `.pth` files are a blind spot.** Most security tooling and developer awareness focuses on `setup.py`, `__init__.py`, and post-install scripts. The `.pth` mechanism — which executes on every interpreter startup, not just at install time — is poorly understood and rarely monitored, making it an ideal attack vector.

2. **Maintainer account security is the critical control.** This attack did not rely on typosquatting or dependency confusion — it hijacked legitimate, trusted packages through compromised maintainer accounts. PyPI's adoption of mandatory 2FA and trusted publishing (OIDC-based) are necessary but not sufficient defenses.

3. **Polyglot payloads evade ecosystem-specific scanners.** By downloading the Bun runtime and executing JavaScript from a Python package, the attackers bypassed Python-focused static analysis. Detection must account for cross-language execution chains.

4. **Destructive anti-response capabilities are escalating.** The dead-man switch (`rm -rf ~/` on token revocation) and geofenced destructive payloads represent a concerning evolution in supply chain malware — punishing defenders who respond correctly by revoking stolen tokens.

5. **Exfiltration via legitimate services is increasingly difficult to detect.** Using GitHub's own API and the Session/Oxen encrypted messaging protocol for exfiltration makes network-based detection challenging without endpoint context.

## Sources

- [Security Online — PyPI Supply Chain Attack](https://securityonline.info/pypi-supply-chain-attack/) — initial advisory on the Hades Cluster campaign
- [Hendry Adrian — Shai-Hulud Descends to Hades](https://www.hendryadrian.com/shai-hulud-descends-to-hades-miasma-worm-campaign-spreads-with-new-pypi-wave/) — detailed technical writeup with package list and IOCs
- [Snyk — Lightning PyPI Compromise: Bun-Based Stealer](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) — technical analysis of the related lightning compromise with file hashes and execution chain
- [JFrog — Shai-Hulud: Here We Go Again](https://research.jfrog.com/post/shai-hulud-here-we-go-again/) — C2 infrastructure analysis and comprehensive IOC list
- [Socket.dev — PyTorch Lightning PyPI Package Compromised](https://socket.dev/blog/lightning-pypi-package-compromised) — initial detection and timeline
- [Socket.dev — Mini Shai-Hulud](https://socket.dev/supply-chain-attacks/mini-shai-hulud) — campaign overview and package tracking
- [StepSecurity — litellm: Credential Stealer Hidden in PyPI Wheel](https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel) — .pth mechanism analysis

<!-- revision-v1: (1) fixed defanging: C2 table 83.142.209.194 → 83.142.209[.]194; (2) Sigma DNS rule: title mismatch fixed (was "Hades Cluster GitHub Exfiltration via GraphQL createCommitOnBranch", now "GitHub API DNS Query from Bun or Python Process" — rule only detects DNS, not GraphQL); confidence medium→low; added FP caveat for dev envs; (3) Suricata sid 2200004 getsession.org: confidence broken out as medium (not high); added caveat re legitimate Session messaging service; (4) T1546.016 verified — exists in ATT&CK as "Installer Packages", closest fit for .pth hook mechanism. -->
<!-- revision-v2: (5) defanged all remaining un-defanged IPs in report prose — MITRE ATT&CK table (T1071.001), detection rules intro, Snort/Suricata prose descriptions; rule code retains real values per encoding spec; (6) re-validated Sigma DNS rule (sigma check 0, splunk 0, log_scale 0) and Suricata getsession rule (suricata -T 0); (7) wrote standalone rule files under rules/{sigma,snort,suricata,yara}/. -->

---
*Report generated by Actioner*
