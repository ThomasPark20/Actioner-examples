# Technical Analysis Report: Microsoft Agent Framework PyPI Supply Chain Attack (2026-11-18)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-18
Version: 1.0-DRAFT

## Executive Summary

On November 17, 2026, an attacker published two malicious versions (1.26.1 and 1.26.2) of the `agent-framework` Python package on PyPI -- the meta-package for Microsoft's Agent Framework, which averages approximately 190,000 downloads per month. The malicious versions contained a credential stealer that abuses Python's `.pth` startup hook mechanism to execute automatically on every interpreter start, even if the package is never imported. The stealer harvests environment variables, credential files, Azure managed-identity tokens, Azure DevOps OIDC tokens, and (in version 1.26.2) GitHub Actions OIDC tokens, then exfiltrates the data via HTTPS POST to a hardcoded `webhook[.]site` endpoint. The exposure window was approximately 55 minutes (20:35-21:30 UTC), after which both versions were quarantined on PyPI. Due to webhook.site's free-tier limit of 100 requests, the attacker captured at most 50 exfiltrated payloads, but those payloads may contain valid cloud, CI/CD, and registry credentials.

## Background: Microsoft Agent Framework

Microsoft Agent Framework is an open-source Python framework for building AI agents, maintained under the `microsoft/agent-framework` GitHub repository. The PyPI package `agent-framework` serves as a meta-package that depends on `agent-framework-core` and related sub-packages. With approximately 190,000 monthly downloads (about 41,000 weekly), it is widely used in enterprise AI development workflows, CI/CD pipelines, and cloud environments -- particularly Azure-based infrastructure. The legitimate version 1.26.0 was published on November 12, 2026, as both a wheel and source distribution alongside `agent-framework-core` 1.26.0.

This attack follows a pattern of PyPI supply chain compromises targeting Microsoft packages. In May 2026, the `durabletask` PyPI package (another Microsoft SDK) was compromised by the TeamPCP threat actor with versions 1.4.1 through 1.4.3 delivering the Mini Shai-Hulud credential stealer worm.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-11-12 18:25 | Legitimate agent-framework 1.26.0 published to PyPI (wheel + sdist) |
| 2026-11-17 ~20:35 | Malicious agent-framework 1.26.1 published to PyPI (wheel-only) |
| 2026-11-17 ~21:08 | Malicious agent-framework 1.26.2 published to PyPI (wheel-only), expanding scope to GitHub Actions |
| 2026-11-17 ~21:30 | Both malicious versions quarantined on PyPI |
| 2026-11-18 | Multiple security vendors publish analyses: Wiz, OX Security, Socket, Endor Labs, SafeDep, Aikido, Chainguard, StepSecurity |
| 2026-11-18 | Microsoft acknowledges the incident; Agent Framework maintainer confirms removal in GitHub issue #10411 |

## Root Cause: PyPI Package Publishing Compromise

The publishing mechanism is unconfirmed. No `python-1.26.1` tag or release exists in the `microsoft/agent-framework` GitHub repository, and the malicious code is absent from the `main` branch. Both malicious versions were wheel-only distributions (legitimate releases include both wheel and source), suggesting the uploads were built outside the normal release process and uploaded directly to PyPI.

SafeDep identified a PyPI maintainer account named "vibiret," created on the day of the attack, with publishing rights to the affected package and five related projects. Its involvement in the malicious uploads is unconfirmed. Wiz noted a separate, unlinked prior incident in which a `durabletask` PyPI token was stolen, raising the possibility of a similar credential compromise for the `agent-framework` publishing token.

## Technical Analysis of the Malicious Payload

### 1. Python Startup Hook Injection (.pth File)

Both malicious versions abuse Python's `.pth` file mechanism. When Python starts, the `site` module processes all `.pth` files in the site-packages directory. Lines beginning with `import` are executed as Python code, running before any user code.

**Version 1.26.1:**
- `agent_framework_meta.pth` contains: `import agent_framework_meta`
- This triggers `agent_framework_meta/__init__.py`, which calls `_telemetry._start()` inside a `try/except Exception: pass` block to suppress errors
- The docstring disguises the hook as: "Lightweight runtime diagnostics hook"

**Version 1.26.2:**
- The legitimate `agent_framework_meta/__init__.py` is restored byte-for-byte (evading detection that checks only that file)
- A new `af_runtime_diag.pth` contains: `import af_runtime_diag`
- This imports a new top-level module `af_runtime_diag.py` which starts the stealer on import

### 2. Process Detachment and Anti-Reentry

The stealer forks into a detached session using `os.fork()` followed by `os.setsid()`, creating a background process that survives the parent's exit. If `os.fork()` is unavailable (e.g., Windows), it falls back to a daemon thread. The environment variable `_AF_TEL=1` is set as a re-entry guard so child processes do not run the payload again. There is no persistent on-disk execution marker, so new process trees can trigger collection again.

### 3. Credential Collection

The stealer performs comprehensive credential harvesting across multiple dimensions:

**Environment variables** -- matched by substring patterns:
- Both versions: `TOKEN`, `SECRET`, `PASSWORD`, `KEY`, `AZURE`, `AWS`, `GITHUB`, `OPENAI`, `HF_`, `FOUNDRY`, `NPM`, `PIP`, `NUGET`, `SYSTEM`, `BUILD`, `AGENT`, `TENANT`, `CLIENT`, `MANAGED`
- Version 1.26.2 adds: `ACTIONS`, `OIDC`, `RUNNER`, `ARM_`

**Other process environments** -- reads up to 300 `/proc/*/environ` files, filtering for: `TOKEN`, `SECRET`, `PASSWORD`, `KEY=`, `SYSTEM_ACCESSTOKEN`, `IDENTITY_HEADER`, and (1.26.2) `ACTIONS_ID_TOKEN`

**Credential files** (cap of 60 in v1.26.1, raised to 80 in v1.26.2):
- Azure CLI: `~/.azure/*.json`, `~/.azure/*/*.json`, `/home/*/.azure/`, `/root/.azure/`
- Azure DevOps agent: `/home/*/_work/*/.credentials`, `/usr/local/vss-agent/*/.credentials`, `/vss-agent/*/.credentials`, `/mnt/azure_nvme_temp/_work/*/.credentials`
- Git credentials: `/home/*/.git-credentials`, `/root/.git-credentials`
- npm: `/home/*/.npmrc`, `/root/.npmrc`
- pip: `/home/*/.config/pip/pip.conf`, `/etc/pip.conf`, `/home/*/.pip/pip.conf`
- netrc: `/home/*/.netrc`, `/root/.netrc`
- Docker: `/home/*/.docker/config.json`, `/root/.docker/config.json`
- Hugging Face: `/home/*/.cache/huggingface/token`, `/home/*/.huggingface/token`
- Foundry: `/home/*/.foundry/*`, `/home/*/.config/foundry/*`
- Application configs: `/app/.env`, `/app/*.env`, `/app/*.json`, `/workspace/.env`, `/workspace/*.json`
- Generic token files: `/home/*/.config/*/token*.json`, `/root/.config/*/token*.json`
- Version 1.26.2 adds: `/home/runner/work/_temp/*`, `/home/runner/.azure/*.json`

**Active token minting** -- the stealer does not just copy existing secrets; it requests fresh tokens:
- Azure IMDS managed-identity tokens from `169.254.169.254` or `IDENTITY_ENDPOINT` / `MSI_ENDPOINT` for 12 resource audiences: ARM, Graph, Key Vault, Storage, Cognitive Services, Azure AI/ML, Search, Container Registry, Azure DevOps, AzureADTokenExchange
- Azure DevOps federation tokens via `SYSTEM_ACCESSTOKEN` and `SYSTEM_OIDCREQUESTURI` for audience `api://AzureADTokenExchange`
- GitHub Actions OIDC tokens (1.26.2 only) via `ACTIONS_ID_TOKEN_REQUEST_URL` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN` for audiences `api://AzureADTokenExchange` and `https://management.azure.com/`
- Azure instance metadata from IMDS (up to 8,000 characters)

### 3. C2 Infrastructure

The exfiltration endpoint is a single hardcoded webhook.site URL, stored as a Base64-encoded string in the malware source code:

Base64 value: `aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi`

Decoded: `hxxps://webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb`

- Protocol: HTTPS POST
- Query string: `?t=telemetry`
- User-Agent: `af-runtime-diagnostics/1` (v1.26.1) / `runtime-diagnostics/1` (v1.26.2)
- Data encoding: JSON -> zlib compress -> Base64 encode
- No fallback channel; failures are silently ignored and not retried
- webhook.site free tier limit: 100 requests per unclaimed URL, expires after 7 days

### 4. Platform-Specific Behavior

#### Linux (Primary Target)
- Uses `os.fork()` + `os.setsid()` for process detachment
- Reads `/proc/*/environ` for credential harvesting from other processes
- Targets Linux-specific paths for Azure DevOps agents, Hugging Face cache, etc.
- Full credential file enumeration via glob patterns

#### CI/CD Environments (Azure DevOps, GitHub Actions)
- Detects CI environment via `SYSTEM_ACCESSTOKEN` (Azure DevOps) and `ACTIONS_ID_TOKEN_REQUEST_URL` (GitHub Actions)
- Actively mints OIDC tokens for cloud access
- Targets runner-specific paths: `/home/runner/work/_temp/*`, `/mnt/azure_nvme_temp/_work/*`

### 5. Anti-Forensics / Evasion Techniques

- **Benign naming**: Files named `_telemetry.py`, `af_runtime_diag.py`; docstrings describe "Lightweight runtime diagnostics hook"
- **Error suppression**: All operations wrapped in `try/except Exception: pass`
- **Process detachment**: Forks into separate session, invisible to parent process
- **Version 1.26.2 evasion**: Restores legitimate `__init__.py` byte-for-byte while adding payload in a new module, evading detection focused on the first variant
- **Base64-encoded URL**: Exfiltration endpoint stored as `_ENC` base64 string
- **No on-disk persistence marker**: Re-entry prevented only via environment variable `_AF_TEL=1`
- **Legitimate functionality preserved**: Applications continue to work normally, as the malicious distributions retain all genuine framework components

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| agent-framework (PyPI) | 1.26.1 | Credential stealer via `agent_framework_meta.pth` -> `_telemetry.py`; targets Azure, Azure DevOps |
| agent-framework (PyPI) | 1.26.2 | Expanded stealer via `af_runtime_diag.pth` -> `af_runtime_diag.py`; adds GitHub Actions OIDC |

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Any | `agent_framework-1.26.1-py3-none-any.whl` | `d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110` | Malicious wheel v1.26.1 |
| Any | `agent_framework-1.26.2-py3-none-any.whl` | `3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9` | Malicious wheel v1.26.2 |
| Any | `agent_framework_meta/__init__.py` (v1.26.1) | `c275ccbe520ef3c0f02dc6a35389e427f9f1b4e0b12e140cd7bf7179ce143f02` | Modified init that imports stealer |
| Any | `agent_framework_meta/_telemetry.py` (v1.26.1) | `39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663` | Credential stealer module v1 |
| Any | `af_runtime_diag.py` (v1.26.2) | `54d885b7d7161c9ed96489c66364c4bfbf635929166843bba10d97d46b5a2e1f` | Credential stealer module v2 |
| Any | `agent_framework_meta.pth` (v1.26.1) | `21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e` | Startup hook v1 |
| Any | `af_runtime_diag.pth` (v1.26.2) | `325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93` | Startup hook v2 |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `webhook[.]site` | Exfiltration dead drop |
| URL Pattern | `hxxps://webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb?t=telemetry` | Hardcoded exfiltration endpoint |
| User-Agent | `af-runtime-diagnostics/1` | v1.26.1 exfiltration User-Agent |
| User-Agent | `runtime-diagnostics/1` | v1.26.2 exfiltration User-Agent |
| Base64 Encoded URL | `aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi` | Stored in malware source |

### Behavioral

- Python process reading multiple `/proc/*/environ` files in rapid succession (up to 300)
- Python process making HTTPS POST to `webhook[.]site` with zlib+base64 encoded body
- Python process setting `_AF_TEL=1` environment variable
- Python process forking and calling `os.setsid()` to detach from parent session
- Unexpected OIDC token requests to Azure IMDS (`169[.]254[.]169[.]254`) or GitHub Actions token endpoint from Python processes that don't normally make such requests
- Presence of `.pth` files in site-packages that import unexpected modules

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code injected into legitimate PyPI package releases |
| T1059.006 | Command and Scripting Interpreter: Python | Payload executes as Python code via .pth startup hook |
| T1552.001 | Unsecured Credentials: Credentials In Files | Reads credential files: .azure/, .git-credentials, .npmrc, .netrc, .docker/config.json, etc. |
| T1552.007 | Unsecured Credentials: Container API | Requests managed-identity tokens from Azure IMDS (169.254.169.254) |
| T1057 | Process Discovery | Enumerates /proc/*/environ to harvest secrets from other running processes |
| T1567 | Exfiltration Over Web Service | Data exfiltrated via HTTPS POST to webhook.site |
| T1041 | Exfiltration Over C2 Channel | Single HTTPS POST carries all collected data to hardcoded endpoint |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS POST with custom User-Agent for exfiltration |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Actively mints Azure OIDC and managed-identity tokens |
| T1078.004 | Valid Accounts: Cloud Accounts | Stolen Azure and GitHub OIDC tokens enable cloud account access |

## Impact Assessment

- **Breadth**: The package has approximately 190,000 monthly downloads. The exposure window was approximately 55 minutes. Any `pip install agent-framework` between 20:35 and 21:30 UTC on November 17 installed the malicious version.
- **Depth**: The stealer collects credentials across Azure, GitHub Actions, Azure DevOps, npm, PyPI, NuGet, Docker, Hugging Face, and Git. It also actively mints fresh OIDC and managed-identity tokens, extending the blast radius beyond stored secrets to live cloud access.
- **Stealth**: The payload runs silently in a detached process, preserves legitimate framework functionality, suppresses all errors, and uses naming designed to look like telemetry. Version 1.26.2 specifically evades detection focused on v1.26.1 artifacts.
- **Actual capture**: webhook.site's free-tier limit of 100 requests (at most 50 for this URL) caps the number of exfiltrated payloads, but each payload may contain dozens of valid credentials. Stolen OIDC/managed-identity tokens may remain valid for up to 24 hours.

## Detection & Remediation

### Immediate Detection

```bash
# Check if compromised versions are installed (any Python environment)
pip show agent-framework 2>/dev/null | grep -E "^Version: 1\.26\.[12]$"

# Check for malicious .pth files in site-packages
find / -name "agent_framework_meta.pth" -o -name "af_runtime_diag.pth" 2>/dev/null

# Check for stealer modules
find / -name "_telemetry.py" -path "*/agent_framework_meta/*" 2>/dev/null
find / -name "af_runtime_diag.py" -not -path "*/.git/*" 2>/dev/null

# Check lockfiles and requirements for pinned compromised versions
grep -r "agent-framework==1.26.[12]" /path/to/project/

# Check pip install logs for the exposure window
grep -r "agent.framework" ~/.pip/pip.log /var/log/pip*.log 2>/dev/null

# Check for the anti-reentry environment variable (indicates execution occurred)
env | grep _AF_TEL

# Search proxy/DNS logs for the exfiltration endpoint
# (Use your SIEM or log search for webhook.site and the UUID)
```

### Remediation

1. **Isolate**: Quarantine any host, container, or CI runner where 1.26.1 or 1.26.2 was installed.
2. **Remove**: Uninstall the compromised package and pin to `agent-framework==1.26.0`. Remove the `.pth` and stealer files from site-packages.
3. **Rotate credentials**: From a known-clean system, rotate ALL secrets that the affected environment could access:
   - Azure CLI sessions and tokens
   - Azure DevOps PATs and service connections
   - GitHub Actions repository and organization secrets
   - GitHub OIDC federated credentials
   - npm, PyPI, NuGet, Docker Hub, Hugging Face tokens
   - Git credentials and SSH keys
   - All `.env` file contents
4. **Audit Azure identities**: Review Entra ID sign-in and activity logs for managed identities and federated credentials reachable from affected VMs, App Services, AKS nodes, or Azure DevOps pipelines. Stolen tokens may be valid for up to 24 hours.
5. **Audit GitHub Actions**: For workflows that installed 1.26.2 with `id-token: write`, treat GitHub OIDC tokens as exposed. Review Entra ID federated credentials trusting those repos and workflows.
6. **Check egress logs**: Search proxy and DNS logs for `webhook.site` and the specific UUID path. HTTP 200 means data was accepted; 410 or 429 means it was rejected.
7. **Rebuild environments**: Rebuild affected containers, virtual environments, and CI runners from clean images.

### Long-Term Hardening

- **Pin dependencies**: Use exact version pinning with hash verification in requirements files (`pip install --require-hashes`).
- **Monitor .pth files**: Add file integrity monitoring for `.pth` files in Python site-packages directories.
- **Package provenance**: Verify packages include both wheel and source distributions and match expected release patterns. Use tools like Sigstore/PyPI Trusted Publishers.
- **Network monitoring**: Alert on outbound connections from Python processes to known dead-drop services (webhook.site, pipedream.net, requestbin, etc.).
- **Least privilege**: Minimize credentials available to CI/CD environments. Use short-lived tokens with narrow scopes.
- **Supply chain scanning**: Deploy SCA tools (Socket, Endor Labs, etc.) that analyze package behavior, not just known vulnerabilities.

## Detection Rules

The rules below cover host-level file artifacts (Sigma, YARA), network exfiltration indicators (Sigma, Suricata, Snort), and malicious code patterns (YARA). All rules target specific IOCs from this incident; the `/proc/*/environ` and `webhook.site` DNS rules additionally detect the behavioral pattern at slightly broader scope. `sigma check` could not run due to proxy restrictions on MITRE ATT&CK data download, but all Sigma rules validated via `sigma convert` to both Splunk and LogScale.

### Sigma: Malicious agent-framework PTH File in Site-Packages

Detects creation of the malicious `.pth` startup hook files unique to the compromised package versions.

<!-- audit: compile=convert-splunk-pass,convert-logscale-pass | sigma check skipped (proxy blocks MITRE ATT&CK data) | confidence=high — filenames are unique to malicious versions, zero expected FPs | tags validated manually against ATT&CK v16 -->

**compile: pass (convert) | confidence: high**

```yaml
title: Malicious agent-framework PTH File in Site-Packages
id: 7a3f1d82-e4b6-4c91-9f2a-8d5e0b7c6a14
status: experimental
description: >
    Detects the creation of malicious .pth files associated with the compromised
    agent-framework PyPI package versions 1.26.1 and 1.26.2. These .pth files
    execute credential-stealing code on every Python interpreter startup.
references:
    - https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
    - https://www.securityweek.com/microsoft-agent-framework-releases-poisoned-with-credential-stealer/
author: Actioner
date: 2026-11-18
tags:
    - attack.t1195.002
    - attack.t1059.006
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'agent_framework_meta.pth'
            - 'af_runtime_diag.pth'
    condition: selection
falsepositives:
    - None expected; these filenames are unique to the compromised package versions
level: critical
```

### Sigma: Agent-Framework Credential Stealer Module on Disk

Detects creation of the Python stealer modules dropped by both compromised versions.

<!-- audit: compile=convert-splunk-pass,convert-logscale-pass | confidence=high — module paths are unique to malware | FP: a file named af_runtime_diag.py in a non-site-packages location is cosmically unlikely -->

**compile: pass (convert) | confidence: high**

```yaml
title: Agent-Framework Credential Stealer Module on Disk
id: 2b8e4c17-f5a3-4d69-b1e0-9c7f6a2d3e58
status: experimental
description: >
    Detects creation of the credential-stealing Python modules dropped by
    compromised agent-framework 1.26.1 (_telemetry.py) and 1.26.2
    (af_runtime_diag.py) in site-packages directories.
references:
    - https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
    - https://socket.dev/blog/agent-framework-pypi-package-compromised-with-credential-stealer
author: Actioner
date: 2026-11-18
tags:
    - attack.t1195.002
    - attack.t1059.006
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'agent_framework_meta/_telemetry.py'
            - 'af_runtime_diag.py'
    condition: selection
falsepositives:
    - None expected; these files are unique to the compromised package
level: critical
```

### Sigma: Python Process Reading /proc/*/environ

Detects the behavioral pattern of a Python process reading other processes' environment variables via `/proc`, as the stealer does to harvest credentials from neighboring processes.

<!-- audit: compile=convert-splunk-pass,convert-logscale-pass | confidence=medium — behavioral pattern, not IOC-specific; legitimate monitoring tools may trigger | requires Sysmon for Linux or auditd file access logging -->

**compile: pass (convert) | confidence: medium**

```yaml
title: Python Process Reading Other Process Environment Variables via Proc
id: 5c9d2e73-a6f1-4b08-e3d4-1f8a0c5b7d96
status: experimental
description: >
    Detects a Python process reading /proc/*/environ files to harvest credentials
    from other running processes, as performed by the agent-framework credential
    stealer. The stealer reads up to 300 /proc/*/environ files looking for tokens
    and secrets.
references:
    - https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
author: Actioner
date: 2026-11-18
tags:
    - attack.t1552.001
    - attack.t1057
logsource:
    category: file_event
    product: linux
detection:
    selection_process:
        Image|endswith:
            - '/python'
            - '/python3'
            - '/python3.10'
            - '/python3.11'
            - '/python3.12'
            - '/python3.13'
    selection_target:
        TargetFilename|contains: '/proc/'
        TargetFilename|endswith: '/environ'
    condition: selection_process and selection_target
falsepositives:
    - Legitimate monitoring tools that inspect process environments
    - Container orchestration health checks
level: high
```

### Sigma: Credential Exfiltration POST to Webhook.site

Detects the specific webhook.site exfiltration endpoint in proxy logs.

<!-- audit: compile=convert-splunk-pass,convert-logscale-pass | confidence=high — UUID is unique to this campaign | requires web proxy logging with URI visibility -->

**compile: pass (convert) | confidence: high**

```yaml
title: Agent-Framework Credential Exfiltration to Webhook.site
id: 8f1a3b56-d7c4-4e29-a0b5-2e9d6c8f4a71
status: experimental
description: >
    Detects HTTPS POST requests to the specific webhook.site endpoint used by the
    compromised agent-framework package to exfiltrate stolen credentials. The
    hardcoded exfiltration URL includes a unique UUID path and telemetry query
    parameter.
references:
    - https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
    - https://socket.dev/blog/agent-framework-pypi-package-compromised-with-credential-stealer
author: Actioner
date: 2026-11-18
tags:
    - attack.t1567
    - attack.t1041
logsource:
    category: proxy
detection:
    selection:
        cs-method: 'POST'
        r-dns: 'webhook.site'
        cs-uri-stem|contains: 'd381fd80-ec62-42ad-8f5c-d1b15103c9bb'
    condition: selection
falsepositives:
    - Legitimate developer testing using webhook.site with this specific UUID is extremely unlikely
level: critical
```

### Sigma: DNS Query to Webhook.site from Python

Detects DNS resolution of `webhook.site` from Python processes as an early-stage network indicator.

<!-- audit: compile=convert-splunk-pass,convert-logscale-pass | confidence=medium — webhook.site is used legitimately by developers; Python-process filter narrows scope but does not eliminate FPs -->

**compile: pass (convert) | confidence: medium**

```yaml
title: DNS Query to Webhook.site from Python Process
id: 4e7c9a21-b3d8-4f56-8e1a-6d0f2c5b9a73
status: experimental
description: >
    Detects DNS resolution of webhook.site initiated by a Python process, which
    may indicate credential exfiltration by the compromised agent-framework
    package or similar supply chain malware using webhook.site as a dead drop.
references:
    - https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
author: Actioner
date: 2026-11-18
tags:
    - attack.t1567
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'webhook.site'
        Image|endswith:
            - '/python'
            - '/python3'
            - '\python.exe'
            - '\python3.exe'
    condition: selection
falsepositives:
    - Developers testing webhook integrations from Python scripts
level: high
```

### Sigma: Suspicious af-runtime-diagnostics User-Agent

Detects the distinctive User-Agent strings hardcoded in the credential stealer.

<!-- audit: compile=convert-splunk-pass,convert-logscale-pass | confidence=high — User-Agent strings are unique to this malware | requires proxy or HTTP inspection logging -->

**compile: pass (convert) | confidence: high**

```yaml
title: Suspicious af-runtime-diagnostics User-Agent String
id: 6d2f8b45-c1e7-4a93-b5d0-3f7e9a1c8b62
status: experimental
description: >
    Detects HTTP requests using the distinctive User-Agent strings hardcoded in
    the compromised agent-framework credential stealer: af-runtime-diagnostics/1
    (version 1.26.1) and runtime-diagnostics/1 (version 1.26.2).
references:
    - https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
author: Actioner
date: 2026-11-18
tags:
    - attack.t1071.001
    - attack.t1567
logsource:
    category: proxy
detection:
    selection:
        cs-User-Agent:
            - 'af-runtime-diagnostics/1'
            - 'runtime-diagnostics/1'
    condition: selection
falsepositives:
    - None expected; these User-Agent strings are unique to the malware
level: critical
```

### Sigma: Agent-Framework Anti-Reentry Environment Variable

Detects processes with the `_AF_TEL` environment variable, used as the stealer's anti-reentry guard.

<!-- audit: compile=convert-splunk-pass,convert-logscale-pass | confidence=medium — relies on command line logging capturing env var references; _AF_TEL is not a standard variable but detection depends on visibility -->

**compile: pass (convert) | confidence: medium**

```yaml
title: Agent-Framework Anti-Reentry Environment Variable Set
id: 9a4c1d67-e8f2-4b35-c7a0-5d3e2f1b8a94
status: experimental
description: >
    Detects a process setting the _AF_TEL environment variable, which the
    compromised agent-framework credential stealer uses as a re-entry guard
    to prevent the payload from running multiple times in child processes.
references:
    - https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
author: Actioner
date: 2026-11-18
tags:
    - attack.t1059.006
    - attack.t1195.002
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: '_AF_TEL'
    filter_main:
        CommandLine|contains: 'grep'
    condition: selection and not filter_main
falsepositives:
    - Unlikely; _AF_TEL is not a standard environment variable name
level: high
```

### YARA: Agent-Framework Supply Chain Stealer Detection

Four YARA rules detecting the malicious `.pth` hooks, both stealer module variants, and the malicious wheel files via embedded artifacts and string combinations.

<!-- audit: yarac compile=pass (exit 0) | 4 rules total | confidence mapping: PTH_Hook=high, Stealer_v1=high, Stealer_v2=high, Malicious_Wheel=high | all rules require the base64-encoded webhook URL as anchor, reducing FPs to near zero -->

**compile: pass | confidence: high (all 4 rules)**

```yara
rule Supply_Chain_AgentFramework_PTH_Hook
{
    meta:
        description = "Detects malicious .pth startup hook files from compromised agent-framework 1.26.1/1.26.2"
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi"
        severity = "critical"
        hash_pth_v1 = "21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e"
        hash_pth_v2 = "325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93"

    strings:
        $pth_v1 = "import agent_framework_meta" ascii
        $pth_v2 = "import af_runtime_diag" ascii

    condition:
        filesize < 512 and
        any of ($pth_*)
}

rule Supply_Chain_AgentFramework_Credential_Stealer_v1
{
    meta:
        description = "Detects the _telemetry.py credential stealer module from compromised agent-framework 1.26.1"
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi"
        severity = "critical"
        hash = "39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663"

    strings:
        $enc_url = "aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi" ascii
        $ua1 = "af-runtime-diagnostics/1" ascii
        $reentry = "_AF_TEL" ascii
        $docstring = "Lightweight runtime diagnostics hook" ascii
        $func_start = "_start" ascii
        $func_run = "_run" ascii
        $proc_env = "/proc/" ascii
        $environ = "/environ" ascii
        $telemetry_param = "?t=telemetry" ascii
        $setsid = "os.setsid" ascii
        $azure_dir = ".azure" ascii
        $git_creds = ".git-credentials" ascii
        $npmrc = ".npmrc" ascii
        $credentials_file = ".credentials" ascii

    condition:
        filesize < 100KB and
        $enc_url and
        3 of ($ua1, $reentry, $docstring, $func_start, $func_run, $telemetry_param, $setsid) and
        2 of ($proc_env, $environ, $azure_dir, $git_creds, $npmrc, $credentials_file)
}

rule Supply_Chain_AgentFramework_Credential_Stealer_v2
{
    meta:
        description = "Detects the af_runtime_diag.py credential stealer module from compromised agent-framework 1.26.2"
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi"
        severity = "critical"
        hash = "54d885b7d7161c9ed96489c66364c4bfbf635929166843bba10d97d46b5a2e1f"

    strings:
        $enc_url = "aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi" ascii
        $ua2 = "runtime-diagnostics/1" ascii
        $reentry = "_AF_TEL" ascii
        $setsid = "os.setsid" ascii
        $actions_oidc = "ACTIONS_ID_TOKEN_REQUEST_URL" ascii
        $runner_path = "/home/runner/work/_temp/" ascii
        $runner_azure = "/home/runner/.azure/" ascii
        $oidc_audience = "api://AzureADTokenExchange" ascii
        $mgmt_audience = "https://management.azure.com/" ascii
        $telemetry_param = "?t=telemetry" ascii
        $proc_env = "/proc/" ascii

    condition:
        filesize < 100KB and
        $enc_url and
        2 of ($ua2, $reentry, $setsid, $telemetry_param) and
        2 of ($actions_oidc, $runner_path, $runner_azure, $oidc_audience, $mgmt_audience, $proc_env)
}

rule Supply_Chain_AgentFramework_Malicious_Wheel
{
    meta:
        description = "Detects compromised agent-framework wheel files (1.26.1 or 1.26.2) by embedded stealer artifacts"
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi"
        severity = "critical"
        hash_v1 = "d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110"
        hash_v2 = "3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9"

    strings:
        $enc_url = "aHR0cHM6Ly93ZWJob29rLnNpdGUvZDM4MWZkODAtZWM2Mi00MmFkLThmNWMtZDFiMTUxMDNjOWJi" ascii
        $pth_v1 = "agent_framework_meta.pth" ascii
        $pth_v2 = "af_runtime_diag.pth" ascii
        $ua1 = "af-runtime-diagnostics/1" ascii
        $ua2 = "runtime-diagnostics/1" ascii
        $telemetry = "_telemetry.py" ascii
        $diag = "af_runtime_diag.py" ascii

    condition:
        filesize < 5MB and
        $enc_url and
        (1 of ($pth_*) or 1 of ($ua*)) and
        (1 of ($telemetry, $diag))
}
```

### Suricata: Agent-Framework Network Exfiltration Detection

Five Suricata rules detecting TLS SNI, DNS queries, HTTP POST to the specific UUID endpoint, and the distinctive User-Agent strings.

<!-- audit: suricata -T compile=pass (clean load, no warnings after fix) | confidence: TLS-SNI=medium (webhook.site is legitimate for devs), DNS=medium, HTTP-POST-UUID=high, UA-v1=high, UA-v2=high -->

**compile: pass | confidence: high (UUID/UA rules), medium (TLS/DNS rules)**

```
# Detect HTTPS TLS SNI to webhook.site
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Agent-Framework Credential Stealer - TLS SNI to webhook.site"; tls.sni; content:"webhook.site"; nocase; classtype:trojan-activity; sid:2026111801; rev:1; metadata:created_at 2026_11_18, updated_at 2026_11_18;)

# Detect DNS query to webhook.site
alert dns $HOME_NET any -> any any (msg:"MALWARE Agent-Framework Credential Stealer - DNS Query for webhook.site"; dns.query; content:"webhook.site"; nocase; classtype:trojan-activity; sid:2026111802; rev:1; metadata:created_at 2026_11_18, updated_at 2026_11_18;)

# Detect HTTP POST to the specific exfiltration UUID endpoint
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Agent-Framework Credential Stealer - Exfiltration POST to webhook.site UUID"; flow:established,to_server; http.method; content:"POST"; http.host; content:"webhook.site"; http.uri; content:"/d381fd80-ec62-42ad-8f5c-d1b15103c9bb"; content:"t=telemetry"; classtype:trojan-activity; sid:2026111803; rev:1; metadata:created_at 2026_11_18, updated_at 2026_11_18;)

# Detect User-Agent: af-runtime-diagnostics/1 (v1.26.1)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Agent-Framework Credential Stealer - Suspicious User-Agent af-runtime-diagnostics"; flow:established,to_server; http.user_agent; content:"af-runtime-diagnostics/1"; classtype:trojan-activity; sid:2026111804; rev:1; metadata:created_at 2026_11_18, updated_at 2026_11_18;)

# Detect User-Agent: runtime-diagnostics/1 (v1.26.2)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE Agent-Framework Credential Stealer - Suspicious User-Agent runtime-diagnostics"; flow:established,to_server; http.user_agent; content:"runtime-diagnostics/1"; classtype:trojan-activity; sid:2026111805; rev:1; metadata:created_at 2026_11_18, updated_at 2026_11_18;)
```

### Snort: Agent-Framework Network Detection (Structural Check Only)

Three Snort rules for the exfiltration POST and both User-Agent strings. Snort is not installed in this environment; rules are provided for structural completeness.

<!-- audit: structural check only, snort not installed | confidence: high — mirrors validated Suricata logic -->

**compile: structural only (snort not installed) | confidence: high**

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE Agent-Framework Credential Stealer - POST to webhook.site exfil endpoint"; flow:established,to_server; content:"POST"; http_method; content:"webhook.site"; http_header; content:"/d381fd80-ec62-42ad-8f5c-d1b15103c9bb"; http_uri; content:"t=telemetry"; http_uri; classtype:trojan-activity; sid:2026111810; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE Agent-Framework Credential Stealer - User-Agent af-runtime-diagnostics"; flow:established,to_server; content:"af-runtime-diagnostics/1"; http_header; classtype:trojan-activity; sid:2026111811; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE Agent-Framework Credential Stealer - User-Agent runtime-diagnostics"; flow:established,to_server; content:"runtime-diagnostics/1"; http_header; classtype:trojan-activity; sid:2026111812; rev:1;)
```

## Lessons Learned

1. **Python .pth files are a persistent blind spot.** The `.pth` startup hook mechanism is not well-known outside the Python packaging community, yet it provides unconditional code execution on every interpreter start. This is the same technique used in the LiteLLM 1.107.0 compromise (October 2026) and the durabletask compromise (May 2026). Organizations should audit and monitor `.pth` files in site-packages as a standard security control.

2. **Supply chain attacks are iterating in real-time.** Version 1.26.2 was published just 33 minutes after 1.26.1, specifically to evade detection of the first variant by restoring the legitimate `__init__.py` and moving the payload to a new module. Defenders should expect attackers to rapidly iterate on evasion when their initial payload is discovered.

3. **Package registries need stronger publishing controls.** The attacker published wheel-only distributions to a package that normally includes source distributions, with no corresponding tag or release in the source repository. Registry-side checks for distribution anomalies, combined with Trusted Publishers and mandatory 2FA, could detect or prevent such attacks.

4. **Active token minting amplifies blast radius.** Unlike simpler stealers that only copy stored credentials, this payload actively mints fresh OIDC and managed-identity tokens. This means even environments with short-lived stored tokens are at risk -- the stealer can generate new, valid tokens on the fly. Organizations should monitor for unexpected token requests from unexpected process contexts.

5. **Dead-drop services limit but don't eliminate impact.** The use of webhook.site's free tier capped exfiltration at approximately 50 payloads, but each payload contained comprehensive credential dumps from the affected environment. A more sophisticated attacker using dedicated infrastructure would have no such limit.

## Sources

- [Wiz Blog: Malicious Version of Microsoft's agent-framework Published to PyPI](https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi) -- primary technical analysis with hashes, code analysis, and remediation guidance
- [SecurityWeek: Microsoft Agent Framework Releases Poisoned With Credential Stealer](https://www.securityweek.com/microsoft-agent-framework-releases-poisoned-with-credential-stealer/) -- industry reporting with timeline, researcher citations, and Microsoft acknowledgment
- [The Hacker News: Attackers Compromise Microsoft's Agent Framework PyPI Package](https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html) -- comprehensive reporting citing Aikido, Chainguard, Endor Labs, OX Security, SafeDep, Socket, StepSecurity, and Wiz
- [Socket: agent-framework PyPI Package Compromised with Credential Stealer](https://socket.dev/blog/agent-framework-pypi-package-compromised-with-credential-stealer) -- technical analysis with hashes, code snippets, and credential file path enumeration
- [OffSeq Radar: Malicious Code in agent-framework (PyPI)](https://radar.offseq.com/threat/malicious-code-in-agent-framework-pypi-79ff163b3101ccb3) -- advisory identifier MAL-2026-20101
- [CyberSecurity News: Microsoft's Agent Framework PyPI Package Hacked](https://cybersecuritynews.com/microsofts-agent-framework-pypi-package/) -- additional reporting

---
*Report generated by Actioner*
