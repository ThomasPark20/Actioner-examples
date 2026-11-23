# Technical Analysis Report: Microsoft agent-framework PyPI Supply Chain Attack — Credential Stealer via .pth Startup Hook (2026-11-23)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-11-23
Version: 1.1 (REVISED)

## Executive Summary

On 2026-11-17, an unknown threat actor published two malicious versions (1.26.1 and 1.26.2) of Microsoft's `agent-framework` package on PyPI within a 33-minute window (20:35-21:08 UTC). The package, which serves as the meta-package for Microsoft's AI Agent Framework (~190,000 monthly downloads), was weaponized with a credential stealer that exploits Python's `.pth` startup hook mechanism to execute on **every Python interpreter start** — without requiring any explicit import of the package. The stealer targets Azure CLI token caches, Azure DevOps OIDC tokens, GitHub Actions OIDC tokens (v1.26.2 only), managed-identity tokens from Azure IMDS, and a broad set of credential files and environment variables across cloud, CI/CD, and package-registry contexts. Harvested data is zlib-compressed, Base64-encoded, and exfiltrated via HTTPS POST to a `webhook[.]site` endpoint. Both versions were quarantined by PyPI within approximately 41 minutes, though the attacker demonstrated continued publishing access by uploading 1.26.2 roughly 2 minutes after 1.26.1 was quarantined. The initial access vector — how the attacker obtained PyPI publishing credentials — remains unknown. Version 1.26.0 is the last confirmed clean release.

Severity: **Critical** (official Microsoft package, silent execution on every Python start, broad cloud/CI credential theft, short but non-zero exposure window in a high-download package).

## Background: agent-framework on PyPI

Microsoft's `agent-framework` is the meta-package for the Microsoft Agent Framework, an AI agent development toolkit. It pulls in `agent-framework-core[all]==1.26.0` and related dependencies. With approximately 190,000 monthly downloads (40,000+ weekly per JFrog), it is widely used in development environments, CI/CD pipelines (Azure DevOps, GitHub Actions), and Azure compute instances (App Service, Functions, VMs). The package's prevalence in automated build and deployment environments makes it a high-value supply-chain target: the ambient credentials available in those contexts (managed identities, OIDC federation, pipeline tokens) are precisely what the attacker targeted.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-11-12 18:24 | Clean `agent-framework==1.26.0` published (wheel + sdist, with provenance) |
| 2026-11-17 20:35:20 | Malicious `1.26.1` uploaded (wheel only, no provenance, User-Agent: `RestSharp/106.13.0.0`) |
| 2026-11-17 21:06:16 | `1.26.1` quarantined by PyPI |
| 2026-11-17 21:08:39 | Malicious `1.26.2` uploaded (~2 min after quarantine, same uploader anomalies) |
| 2026-11-17 21:16:44 | `1.26.2` quarantined by PyPI |
| 2026-11-18 | Multiple security vendors publish analyses (JFrog, StepSecurity, Socket, Aikido, others) |
| 2026-11-18 | GitHub Advisory GHSA-764m-3ppc-5m73 published |
| 2026-11-20 | Microsoft acknowledges incident; repos `microsoft/agent-framework` and `microsoft/onnxruntime` made private during investigation |

**Exposure window:** Approximately 41 minutes (20:35 to 21:16 UTC on 2026-11-17). Any `pip install agent-framework` without a pinned version during this window, or any CI/CD pipeline that resolved to the latest version, would have installed the malicious code.

## Root Cause: PyPI Account/Token Compromise → Supply-Chain Injection

The attacker obtained publishing credentials for the `agent-framework` PyPI project. The mechanism is unknown, but publisher anomalies are significant:

- **Uploader User-Agent:** `RestSharp/106.13.0.0` (a .NET HTTP client library, not typical for PyPI publishing)
- **No provenance attestation:** Clean 1.26.0 had provenance; malicious versions did not
- **Wheel-only releases:** Clean 1.26.0 included both wheel and sdist; malicious versions were wheel-only
- **Metadata preserved:** The malicious wheels still declared `agent-framework-core[all]==1.26.0` as a dependency, maintaining apparent legitimacy
- **Rapid re-upload:** The attacker uploaded 1.26.2 within 2 minutes of 1.26.1's quarantine, demonstrating that PyPI's per-version quarantine did not revoke the compromised publishing credential

JFrog's analysis indicates the attacker repacked the clean wheel locally rather than compromising Microsoft's build pipeline.

## Technical Analysis of the Malicious Payload

### 1. Persistence via .pth Startup Hook

Python processes `.pth` files in `site-packages` at interpreter startup. Lines beginning with `import` are executed as Python statements. This mechanism runs before any user code, including `pip` itself.

**Version 1.26.1:**
- Drops `agent_framework_meta.pth` (content: `import agent_framework_meta`) into `site-packages/`
- Creates `agent_framework_meta/__init__.py` with 8 appended lines calling `_telemetry._start()`
- Creates `agent_framework_meta/_telemetry.py` containing the full stealer payload

**Version 1.26.2 (evolved to evade detection):**
- Drops `af_runtime_diag.pth` (23 bytes, content: `import af_runtime_diag`) into `site-packages/`
- Creates `af_runtime_diag.py` (7,658 bytes) as a standalone top-level module containing the stealer
- Restores `agent_framework_meta/__init__.py` to clean content (checking only `__init__.py` would miss the payload)
- Broadens targeting to include GitHub Actions OIDC tokens and `/home/runner` paths
- Increases captured-file limit from 60 to 80

### 2. Execution and Process Behavior

On Python interpreter start:
1. The `.pth` import line triggers the payload module
2. The payload checks for the `_AF_TEL` environment variable (anti-recursion guard)
3. If not set, it sets `_AF_TEL=1` and proceeds
4. On Linux/macOS: calls `os.fork()`, then `os.setsid()` in the child process to detach from the parent; parent calls `os._exit(0)` to continue normal Python execution
5. On Windows: starts a daemon thread instead
6. All exceptions are silently suppressed — no output to stdout/stderr or log files
7. No lockfiles, markers, or persistence artifacts are written to disk beyond the initial `.pth` and module files

### 3. Credential Collection

**Environment Variables** (case-insensitive substring matching, 35 patterns in 1.26.2, 31 in 1.26.1):
`TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `KEY`, `CONNECTION`, `ENDPOINT`, `AZURE`, `AWS`, `GITHUB`, `GH_`, `HF_`, `HUGGING`, `OPENAI`, `FOUNDRY`, `VSS`, `SYSTEM`, `BUILD`, `AGENT`, `CI_`, `PIP`, `NPM`, `NUGET`, `COSMOS`, `STORAGE`, `SUBSCRIPTION`, `TENANT`, `CLIENT`, `IDENTITY`, `MSI`, `MANAGED`, `ACTIONS`, `OIDC`, `RUNNER`, `ARM_`

**Credential Files** (37 glob patterns in 1.26.2, 35 in 1.26.1; files under 262,144 bytes; up to 120,000 chars captured):
- `~/.azure/*.json` — Azure CLI token caches
- `pip.conf`, `.npmrc`, `.netrc`, `.git-credentials` — package registry and SCM credentials
- `.docker/config.json` — Docker registry authentication
- Hugging Face tokens and Foundry configurations
- Azure DevOps agent credential stores (`vss-agent`, `_work`, `/mnt/azure_nvme_temp`)
- Application `.env` files at `/app/` and `/workspace/`
- 1.26.2 adds: `/home/runner/work/_temp/*`, `/home/runner/.azure/*`

**Process Environment Scraping** (Linux only):
- Reads `/proc/[0-9]*/environ` for the first 300 processes
- Extracts values matching: `TOKEN`, `SECRET`, `PASSWORD`, `KEY=`, `ENDPOINT_AUTH`, `SYSTEM_ACCESSTOKEN`, `IDENTITY_HEADER`
- 1.26.2 adds: `ACTIONS_ID_TOKEN`

**Active Token Minting:**
- **Azure DevOps OIDC** (both versions): POSTs to `SYSTEM_OIDCREQUESTURI` using `SYSTEM_ACCESSTOKEN` to obtain a federated token for `api://AzureADTokenExchange`
- **GitHub Actions OIDC** (1.26.2 only): Requests JWTs for `api://AzureADTokenExchange` and `https://management.azure.com/` using `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` (requires `id-token: write` permission)
- **Azure Managed Identity** (both versions): Requests tokens for 12 resources via IMDS (`169[.]254[.]169[.]254`) or `IDENTITY_ENDPOINT`/`MSI_ENDPOINT`. Target resources include: Azure Management, Key Vault (`vault.azure.net`), Storage, Graph, Container Registry, Azure DevOps (`499b84ac-1321-427f-aa17-267ca6975798`), and `api://AzureADTokenExchange`
- Also retrieves Azure IMDS instance metadata (up to 8,000 characters)

### 4. Exfiltration

Collected data is assembled into a JSON document, zlib-compressed, Base64-encoded, and sent via HTTPS POST to:
`hxxps[:]//webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb?t=telemetry`

- **Content-Type:** `application/octet-stream`
- **User-Agent:** `af-runtime-diagnostics/1` (1.26.1) or `runtime-diagnostics/1` (1.26.2)
- The webhook URL is stored Base64-encoded in the `_ENC` variable within the payload

No second-stage remote code loading, scheduled tasks, or additional persistence mechanisms were identified. The `.pth` hook itself provides persistence for the lifetime of the installed package.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs `hxxps://`; domains/IPs use `[.]`; emails `[at]`. Hashes and file paths are not defanged.

### Package / Software Level

| Package | Version | Status | Description |
|---------|---------|--------|-------------|
| `agent-framework` | 1.26.1 | Quarantined | First malicious release; .pth hook + `_telemetry.py` stealer |
| `agent-framework` | 1.26.2 | Quarantined | Second malicious release; renamed payload, expanded targeting |
| `agent-framework` | 1.26.0 | Clean | Last known-good version; pin here |

### File Hashes (SHA-256)

| Artifact | Version | SHA-256 |
|----------|---------|---------|
| `agent_framework-1.26.1-py3-none-any.whl` | 1.26.1 | `d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110` |
| `agent_framework_meta.pth` | 1.26.1 | `21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e` |
| `agent_framework_meta/_telemetry.py` | 1.26.1 | `39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663` |
| `agent_framework_meta/__init__.py` (modified) | 1.26.1 | `c275ccbe520ef3c0f02dc6a35389e427f9f1b4e0b12e140cd7bf7179ce143f02` |
| `agent_framework-1.26.2-py3-none-any.whl` | 1.26.2 | `3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9` |
| `af_runtime_diag.pth` (23 bytes) | 1.26.2 | `325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93` |
| `af_runtime_diag.py` (7,658 bytes) | 1.26.2 | `54d885b7d7161c9ed96489c66364c4bfbf635929166843bba10d97d46b5a2e1f` |

### File System

| Platform | Path / Filename | Description |
|----------|-----------------|-------------|
| Cross-platform | `site-packages/agent_framework_meta.pth` | v1.26.1 startup hook |
| Cross-platform | `site-packages/agent_framework_meta/_telemetry.py` | v1.26.1 stealer payload |
| Cross-platform | `site-packages/agent_framework_meta/__init__.py` | v1.26.1 modified init (appended `_telemetry._start()` call) |
| Cross-platform | `site-packages/af_runtime_diag.pth` | v1.26.2 startup hook |
| Cross-platform | `site-packages/af_runtime_diag.py` | v1.26.2 stealer payload |
| Cross-platform | `__pycache__/af_runtime_diag.*.pyc` | Compiled bytecode (presence does not confirm execution) |

### Network

| Type | Value | Context |
|------|-------|---------|
| URL | `hxxps[:]//webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb?t=telemetry` | Exfiltration endpoint |
| Domain | `webhook[.]site` | Exfiltration service |
| UUID | `d381fd80-ec62-42ad-8f5c-d1b15103c9bb` | Webhook endpoint identifier |
| IP | `169[.]254[.]169[.]254` | Azure IMDS (queried for token theft, not attacker-owned) |
| User-Agent | `af-runtime-diagnostics/1` | v1.26.1 exfil UA |
| User-Agent | `runtime-diagnostics/1` | v1.26.2 exfil UA |

### Behavioral

- `.pth` file in `site-packages` with `import agent_framework_meta` or `import af_runtime_diag`
- Environment variable `_AF_TEL=1` present in process environment (anti-recursion marker)
- Python process forking with `os.setsid()` and `os._exit(0)` pattern
- Reading `/proc/[0-9]*/environ` files (Linux)
- HTTPS POST to `webhook[.]site` with `application/octet-stream` content type from build/CI hosts
- Outbound connections to Azure IMDS from non-Azure-compute environments
- Publisher anomalies: `RestSharp/106.13.0.0` User-Agent on PyPI uploads; wheel-only without provenance

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious versions of official Microsoft package published to PyPI |
| T1546.016 | Event Triggered Execution: Installer Packages | `.pth` startup hook executes stealer on every Python interpreter start |
| T1059.006 | Command and Scripting Interpreter: Python | Payload is Python code triggered by the interpreter's own startup mechanism |
| T1552.001 | Unsecured Credentials: Credentials In Files | Reads `~/.azure/*.json`, `.npmrc`, `.netrc`, `.git-credentials`, `.docker/config.json`, `.env` files |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Queries Azure IMDS at `169[.]254[.]169[.]254` for managed-identity tokens and instance metadata |
| T1528 | Steal Application Access Token | Mints Azure DevOps OIDC tokens, GitHub Actions OIDC tokens, and Azure managed-identity tokens |
| T1003.007 | OS Credential Dumping: Proc Filesystem | Reads `/proc/[0-9]*/environ` to harvest credentials from other processes |
| T1041 | Exfiltration Over C2 Channel | Compressed, encoded credential bundles sent via HTTPS POST to webhook[.]site |
| T1567 | Exfiltration Over Web Service | Uses webhook[.]site (legitimate web service) for data exfiltration |
| T1070 | Indicator Removal on Host | Suppresses all exceptions; writes no logs or markers; v1.26.2 restores clean `__init__.py` to remove evidence of compromise |

## Impact Assessment

**Breadth:** ~190,000 monthly downloads; affects any Python environment that resolved `agent-framework` to 1.26.1 or 1.26.2 during the 41-minute window, including CI/CD runners (Azure DevOps, GitHub Actions), Azure compute (App Service, Functions, VMs), and developer workstations.

**Depth:** Full credential exfiltration across Azure CLI caches, CI/CD pipeline tokens, cloud managed identities, package registry credentials, SCM credentials, and Docker registry authentication. Active token minting via OIDC federation extends the blast radius beyond static credentials to live, short-lived tokens for Azure Management, Key Vault, Storage, Graph, and Container Registry.

**Stealth:** Silent execution via `.pth` hook with no log output, no disk artifacts beyond the initial payload files, process forking/detaching to avoid parent process monitoring, and anti-recursion guard. Version 1.26.2 specifically evolved to evade detection of v1.26.1 artifacts.

**Prior Art:** This incident follows the May 2026 `durabletask` PyPI compromise (TeamPCP / Mini Shai-Hulud worm) targeting another Microsoft package, suggesting a pattern of targeting high-profile Microsoft Python packages on PyPI.

## Detection & Remediation

### Immediate Detection

1. **Package audit:** Search all Python environments, lockfiles (`requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pdm.lock`), dependency caches, internal mirrors, and container images for `agent-framework==1.26.1` or `agent-framework==1.26.2`. Use the SHA-256 wheel hashes for definitive identification.
2. **Filesystem hunt:** Search all `site-packages` directories for `agent_framework_meta.pth`, `af_runtime_diag.pth`, `agent_framework_meta/_telemetry.py`, and `af_runtime_diag.py`. Use trusted tooling — do not start the potentially compromised Python interpreter.
3. **Network hunt:** Search proxy/DNS/firewall logs from build hosts, CI runners, and Azure compute for `webhook[.]site`, the UUID `d381fd80-ec62-42ad-8f5c-d1b15103c9bb`, and the two User-Agent strings. An HTTP 200 response indicates completed exfiltration.
4. **Process hunt:** Search for `_AF_TEL=1` in process environments on live systems.
5. **CI/CD audit:** Review all CI/CD runs from 2026-11-17 onward where Python executed after dependency installation.

### Remediation

1. **Isolate first:** Isolate affected hosts and runners before running Python or pip on them (the payload re-executes on any Python start).
2. **Rebuild clean:** Rebuild from a clean base. Pin `agent-framework==1.26.0` with hashed lockfiles. Block 1.26.1 and 1.26.2 on internal registries and mirrors.
3. **Rotate credentials:** Rotate all credentials the payload could read or request, including: Azure CLI tokens, CI/CD pipeline secrets, cloud API keys, package registry tokens, Git credentials, Docker registry tokens, and Hugging Face tokens. Rotate from a clean system.
4. **Audit identity:** Review Azure sign-in logs, token issuance events, and resource access for the exposure window. Audit OIDC federation trusts, federated credentials, service connections, and managed-identity role assignments. Note: deleting a trust does not revoke tokens already issued.
5. **Audit GitHub Actions:** Review workflows that deploy to Azure, especially those with `id-token: write` permission, for signs of OIDC token theft.

### Long-Term Hardening

- Pin dependencies with hashed lockfiles (`pip install --require-hashes`)
- Restrict CI runner egress to an allowlist (block `webhook[.]site` and other untrusted webhook/pastebin services)
- Use short-lived, scoped CI/CD tokens with OIDC federation rather than long-lived secrets
- Run dependency installation in isolated, least-privilege environments without ambient cloud metadata access
- Monitor for `.pth` file creation in `site-packages` as an anomalous event
- Require provenance attestation for critical dependencies

## Detection Rules

These detections target the Microsoft agent-framework PyPI supply chain compromise at **PoC/advisory-specific** altitude: the `.pth` startup hook files, stealer module creation, webhook[.]site exfiltration, anti-recursion environment marker, and `/proc/environ` scraping. Each rule's compile status and confidence are labeled individually. The Sigma rules' `sigma check` exit 1 is due to the environment's D3FEND egress 403 (not a rule defect); the load-bearing validation is clean conversion to both Splunk SPL and CrowdStrike LogScale.

### Sigma: Malicious agent-framework .pth Startup Hook File Creation
Detects the creation of `.pth` startup hook files (`agent_framework_meta.pth` and `af_runtime_diag.pth`) that trigger the credential stealer on every Python interpreter start.
**Status:** compile ✅ compiles (sigma convert splunk exit=0, log_scale exit=0) · confidence: high
<!-- audit: sigma check exit=1 (D3FEND fetch HTTP 403 egress block — documented env limitation, not a rule defect); sigma convert --without-pipeline -t splunk exit=0; -t log_scale exit=0. Filenames are unique to the malicious versions; zero expected FP. -->
```yaml
title: Malicious agent-framework .pth Startup Hook File Creation
id: a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: >
    Detects the creation of malicious .pth startup hook files dropped by compromised
    versions (1.26.1 and 1.26.2) of Microsoft's agent-framework PyPI package. These
    files (agent_framework_meta.pth and af_runtime_diag.pth) execute a credential
    stealer on every Python interpreter start without requiring an explicit import.
references:
    - https://research.jfrog.com/post/agent-framework-hijack/
    - https://github.com/advisories/GHSA-764m-3ppc-5m73
    - https://www.stepsecurity.io/blog/microsoft-agent-framework-pypi-package-compromised
author: Actioner
date: 2026/11/23
tags:
    - attack.t1195.002
    - attack.t1546.016
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
    - None expected; these filenames are unique to the malicious versions
level: high
```

### Sigma: Malicious agent-framework Credential Stealer Module File Creation
Detects the creation of the stealer payload modules (`agent_framework_meta/_telemetry.py` and `af_runtime_diag.py`).
**Status:** compile ✅ compiles (sigma convert splunk exit=0, log_scale exit=0) · confidence: high
<!-- audit: sigma check exit=1 (D3FEND 403 env block); splunk exit=0; log_scale exit=0. Module paths are unique to the malicious versions. -->
```yaml
title: Malicious agent-framework Credential Stealer Module File Creation
id: b2c3d4e5-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: >
    Detects the creation of malicious Python modules dropped by compromised versions
    of Microsoft's agent-framework PyPI package. Version 1.26.1 drops
    agent_framework_meta/_telemetry.py and version 1.26.2 drops af_runtime_diag.py,
    both containing credential-stealing payloads targeting Azure, CI/CD, and cloud
    credentials.
references:
    - https://research.jfrog.com/post/agent-framework-hijack/
    - https://github.com/advisories/GHSA-764m-3ppc-5m73
author: Actioner
date: 2026/11/23
tags:
    - attack.t1195.002
    - attack.t1059.006
    - attack.t1552.001
logsource:
    category: file_event
detection:
    selection_v1:
        TargetFilename|endswith: 'agent_framework_meta/_telemetry.py'
    selection_v2:
        TargetFilename|endswith: 'af_runtime_diag.py'
    condition: selection_v1 or selection_v2
falsepositives:
    - None expected; these module paths are unique to the malicious versions
level: high
```

### Sigma: agent-framework Credential Exfiltration to webhook.site
Detects network connections to the exfiltration endpoint and the distinctive User-Agent strings used by the stealer.
**Status:** compile ✅ compiles (sigma convert splunk exit=0, log_scale exit=0) · confidence: high (UUID selection), medium (UA selection alone)
<!-- audit: sigma check exit=1 (D3FEND 403 env block); splunk exit=0; log_scale exit=0. The webhook UUID is a near-unique anchor (high); the UA strings are distinctive but shorter (medium on their own, high when paired with webhook.site destination). -->
```yaml
title: agent-framework Credential Exfiltration to webhook.site
id: c3d4e5f6-7a8b-9c0d-1e2f-3a4b5c6d7e8f
status: experimental
description: >
    Detects network connections to the webhook.site exfiltration endpoint used by
    malicious versions 1.26.1 and 1.26.2 of Microsoft's agent-framework PyPI package.
    The stealer sends zlib-compressed, base64-encoded credential bundles via HTTPS POST
    to a specific webhook.site UUID path. Also detects the distinctive User-Agent
    strings used by the payload.
references:
    - https://research.jfrog.com/post/agent-framework-hijack/
    - https://github.com/advisories/GHSA-764m-3ppc-5m73
author: Actioner
date: 2026/11/23
tags:
    - attack.t1041
    - attack.t1567
logsource:
    category: proxy
detection:
    selection_url:
        c-uri|contains: 'd381fd80-ec62-42ad-8f5c-d1b15103c9bb'
    selection_ua:
        c-useragent|contains:
            - 'af-runtime-diagnostics/1'
            - 'runtime-diagnostics/1'
    condition: selection_url or selection_ua
falsepositives:
    - Legitimate use of webhook.site with this specific UUID (extremely unlikely)
level: critical
```

### Sigma: agent-framework Credential Stealer Anti-Recursion Environment Marker
Detects the `_AF_TEL` environment variable used as the stealer's anti-recursion guard.
**Status:** compile ✅ compiles (sigma convert splunk exit=0, log_scale exit=0) · confidence: medium
<!-- audit: sigma check exit=1 (D3FEND 403 env block); splunk exit=0; log_scale exit=0. The _AF_TEL marker is distinctive but short; medium because other telemetry frameworks could theoretically use the same name. Requires process_creation logsource with environment variable capture (e.g., Sysmon Event ID 1 with EnvironmentVariables). The EnvironmentVariables field is Sysmon-specific which limits portability. -->
```yaml
title: agent-framework Credential Stealer Anti-Recursion Environment Marker
id: d4e5f6a7-8b9c-0d1e-2f3a-4b5c6d7e8f9a
status: experimental
description: >
    Detects process creation with the _AF_TEL environment variable set, which is the
    anti-recursion guard used by the malicious agent-framework credential stealer.
    When the payload executes, it sets _AF_TEL=1 via os.environ to prevent re-entry
    on subsequent Python interpreter starts. The presence of this variable in a process
    environment indicates the stealer has executed. Note: This rule relies on the
    Sysmon EnvironmentVariables field (Event ID 1), which limits portability to
    non-Sysmon log sources.
references:
    - https://research.jfrog.com/post/agent-framework-hijack/
    - https://github.com/advisories/GHSA-764m-3ppc-5m73
author: Actioner
date: 2026/11/23
tags:
    - attack.t1059.006
logsource:
    category: process_creation
detection:
    selection_env:
        EnvironmentVariables|contains: '_AF_TEL=1'
    condition: selection_env
falsepositives:
    - Custom telemetry frameworks using the same environment variable name (unlikely)
level: high
```

### Sigma: agent-framework Credential Stealer /proc/environ Scraping
Detects bulk access to `/proc/*/environ` files consistent with the stealer's process environment harvesting.
**Status:** compile ✅ compiles (sigma convert splunk exit=0, log_scale exit=0) · confidence: medium
<!-- audit: sigma check exit=1 (D3FEND 403 env block); splunk exit=0; log_scale exit=0. /proc/*/environ access is a behavioral indicator, not unique to this campaign. Filter list covers common legitimate readers but requires tuning for each environment. Medium confidence due to FP potential from monitoring tools. -->
```yaml
title: agent-framework Credential Stealer /proc/environ Scraping
id: e5f6a7b8-9c0d-1e2f-3a4b-5c6d7e8f9a0b
status: experimental
description: >
    Detects access patterns consistent with the malicious agent-framework credential
    stealer scraping /proc/*/environ to harvest environment variables from other
    processes. The payload reads the first 300 entries looking for TOKEN, SECRET,
    PASSWORD, KEY, and other credential-bearing variable patterns.
references:
    - https://research.jfrog.com/post/agent-framework-hijack/
    - https://www.stepsecurity.io/blog/microsoft-agent-framework-pypi-package-compromised
author: Actioner
date: 2026/11/23
tags:
    - attack.t1552.001
    - attack.t1003.007
logsource:
    category: file_access
    product: linux
detection:
    selection:
        TargetFilename|re: '/proc/[0-9]+/environ'
    filter_known:
        Image|endswith:
            - '/systemd'
            - '/proc'
            - '/ps'
            - '/top'
            - '/htop'
    condition: selection and not filter_known
falsepositives:
    - Monitoring tools, container runtimes, and debugging utilities that read /proc/*/environ
level: medium
```

### Snort: agent-framework PyPI Credential Stealer Exfiltration
Detects HTTP traffic containing the webhook[.]site exfiltration UUID (SID 2100601, **high**), TLS SNI to webhook[.]site (SID 2100602, **medium** — scope to CI hosts), and the distinctive User-Agent strings (SIDs 2100603-2100604).
**Status:** ⚠️ uncompiled (structural check only — all 4 rules pass) · confidence: 2100601/2100603 high · 2100602/2100604 medium
<!-- audit: structural validation pass (alert keyword, msg, sid, rev, classtype, balanced parens). Snort 2 syntax. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - agent-framework PyPI Stealer Exfil webhook.site UUID [HIGH]"; flow:established,to_server; content:"d381fd80-ec62-42ad-8f5c-d1b15103c9bb"; nocase; classtype:trojan-activity; reference:url,research.jfrog.com/post/agent-framework-hijack/; sid:2100601; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - agent-framework PyPI Stealer TLS SNI webhook.site [MEDIUM]"; flow:established,to_server; content:"|16 03|"; depth:2; content:"webhook.site"; nocase; classtype:trojan-activity; reference:url,research.jfrog.com/post/agent-framework-hijack/; sid:2100602; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - agent-framework PyPI Stealer UA af-runtime-diagnostics [HIGH]"; flow:established,to_server; content:"af-runtime-diagnostics/1"; nocase; http_header; classtype:trojan-activity; reference:url,research.jfrog.com/post/agent-framework-hijack/; sid:2100603; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - agent-framework PyPI Stealer UA runtime-diagnostics [MEDIUM]"; flow:established,to_server; content:"runtime-diagnostics/1"; nocase; http_header; classtype:trojan-activity; reference:url,research.jfrog.com/post/agent-framework-hijack/; sid:2100604; rev:1;)
```

### Suricata: agent-framework PyPI Credential Stealer Exfiltration
HTTP URI with webhook UUID and POST method (SID 2200601, **high**), DNS query for webhook[.]site (SID 2200602, **medium**), TLS SNI (SID 2200603, **medium**), and User-Agent strings (SIDs 2200604-2200605).
**Status:** ⚠️ uncompiled (structural check only — all 5 rules pass) · confidence: 2200601/2200604 high · 2200602/2200603/2200605 medium
<!-- audit: structural validation pass (alert keyword, msg, sid, rev, metadata, balanced parens). Suricata 7 syntax. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - agent-framework PyPI Stealer Exfil webhook.site UUID [HIGH]"; flow:established,to_server; http.uri; content:"/d381fd80-ec62-42ad-8f5c-d1b15103c9bb"; http.method; content:"POST"; classtype:trojan-activity; reference:url,research.jfrog.com/post/agent-framework-hijack/; metadata:author Actioner, created_at 2026-11-23; sid:2200601; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - agent-framework PyPI Stealer DNS webhook.site [MEDIUM - scope to CI hosts]"; dns.query; content:"webhook.site"; nocase; classtype:trojan-activity; reference:url,research.jfrog.com/post/agent-framework-hijack/; metadata:author Actioner, created_at 2026-11-23; sid:2200602; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - agent-framework PyPI Stealer TLS SNI webhook.site [MEDIUM - scope to CI hosts]"; flow:established,to_server; tls.sni; content:"webhook.site"; nocase; classtype:trojan-activity; reference:url,research.jfrog.com/post/agent-framework-hijack/; metadata:author Actioner, created_at 2026-11-23; sid:2200603; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - agent-framework PyPI Stealer UA af-runtime-diagnostics [HIGH]"; flow:established,to_server; http.user_agent; content:"af-runtime-diagnostics/1"; classtype:trojan-activity; reference:url,research.jfrog.com/post/agent-framework-hijack/; metadata:author Actioner, created_at 2026-11-23; sid:2200604; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - agent-framework PyPI Stealer UA runtime-diagnostics [MEDIUM]"; flow:established,to_server; http.user_agent; content:"runtime-diagnostics/1"; classtype:trojan-activity; reference:url,research.jfrog.com/post/agent-framework-hijack/; metadata:author Actioner, created_at 2026-11-23; sid:2200605; rev:1;)
```

### YARA: agent-framework PyPI Credential Stealer Payload
Detects the stealer payload files via exfiltration URL components, User-Agent strings, anti-recursion marker, .pth import lines, fork/daemonize pattern, and Azure credential targeting patterns. Two rules: `AgentFramework_PyPI_CredStealer` (full payload) and `AgentFramework_PyPI_PthHook` (the small .pth hook files).
**Status:** ⚠️ uncompiled (structural check only — 2 rules, all checks pass) · confidence: high (webhook UUID / UA / .pth branches), medium (behavioral branches) · sample: constructed
<!-- audit: structural validation pass (rule keyword, meta, strings, condition, balanced braces, 2 rules). Positive built from published strings, not from a confirmed upstream sample. -->
```yara
rule AgentFramework_PyPI_CredStealer
{
    meta:
        description = "Detects the credential stealer payload from malicious versions 1.26.1 and 1.26.2 of Microsoft's agent-framework PyPI package. Matches on distinctive module names, exfiltration URL components, User-Agent strings, anti-recursion marker, and targeted credential file patterns."
        author = "Actioner"
        date = "2026-11-23"
        reference1 = "https://research.jfrog.com/post/agent-framework-hijack/"
        reference2 = "https://github.com/advisories/GHSA-764m-3ppc-5m73"
        hash1 = "d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110"
        hash2 = "3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9"
        hash3 = "39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663"
        hash4 = "54d885b7d7161c9ed96489c66364c4bfbf635929166843bba10d97d46b5a2e1f"
        severity = "critical"

    strings:
        // Anti-recursion environment marker
        $env_marker    = "_AF_TEL" ascii

        // Exfiltration webhook UUID
        $webhook_uuid  = "d381fd80-ec62-42ad-8f5c-d1b15103c9bb" ascii

        // User-Agent strings
        $ua_v1         = "af-runtime-diagnostics/1" ascii
        $ua_v2         = "runtime-diagnostics/1" ascii

        // Module/file names unique to the payload
        $pth_v1        = "agent_framework_meta.pth" ascii
        $pth_v2        = "af_runtime_diag.pth" ascii

        // Persistence mechanism: .pth import line
        $pth_import_v1 = "import agent_framework_meta" ascii
        $pth_import_v2 = "import af_runtime_diag" ascii

        // Forking and daemonization pattern
        $fork_setsid   = "os.setsid()" ascii
        $fork_exit     = "os._exit(0)" ascii

        // Targeted credential paths
        $cred_azure    = ".azure/" ascii
        $cred_npmrc    = ".npmrc" ascii
        $cred_gitcred  = ".git-credentials" ascii
        $cred_docker   = ".docker/config.json" ascii
        $cred_netrc    = ".netrc" ascii

        // Azure IMDS and identity endpoint patterns
        $imds          = "169.254.169.254" ascii
        $oidc_audience = "api://AzureADTokenExchange" ascii

        // Azure DevOps token variables
        $ado_token     = "SYSTEM_ACCESSTOKEN" ascii

    condition:
        // High confidence: webhook UUID or both User-Agent variants
        $webhook_uuid
        or ($ua_v1 and $ua_v2)
        // High confidence: .pth file + corresponding module
        or ($pth_v1 and $pth_import_v1)
        or ($pth_v2 and $pth_import_v2)
        // Medium confidence: anti-recursion marker + fork/daemonize + credential targets
        or ($env_marker and ($fork_setsid or $fork_exit) and 2 of ($cred_azure, $cred_npmrc, $cred_gitcred, $cred_docker, $cred_netrc))
        // Medium confidence: OIDC audience + ADO tokens + IMDS
        or ($oidc_audience and $ado_token and $imds)
}

rule AgentFramework_PyPI_PthHook
{
    meta:
        description = "Detects .pth startup hook files dropped by malicious agent-framework versions. These 23-byte files contain a single import line that triggers the credential stealer on every Python interpreter start."
        author = "Actioner"
        date = "2026-11-23"
        reference = "https://research.jfrog.com/post/agent-framework-hijack/"
        hash = "21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e"
        hash = "325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93"
        severity = "high"

    strings:
        $import_v1 = "import agent_framework_meta" ascii
        $import_v2 = "import af_runtime_diag" ascii

    condition:
        filesize < 100 and any of them
}
```

## Lessons Learned

Python's `.pth` startup hook mechanism is a potent vector for supply-chain attacks: it executes code on every interpreter start without any explicit import, including when `pip` itself runs, making it difficult to avoid execution once a malicious package is installed. The attacker's ability to upload 1.26.2 within 2 minutes of 1.26.1's quarantine highlights a gap in PyPI's incident response: per-version quarantine without revoking the compromised publishing credential allows an attacker to iterate. The absence of provenance attestation on the malicious versions, combined with the anomalous `RestSharp/106.13.0.0` uploader User-Agent and wheel-only format, provides useful heuristics for detecting future supply-chain compromises on PyPI. Organizations relying on Microsoft's AI Agent Framework and other high-profile Python packages should enforce hashed lockfile pins and block known exfiltration services (such as `webhook[.]site`) at the network egress.

## Sources

- [Attackers Compromise Microsoft's Agent Framework PyPI Package to Steal Cloud Credentials — The Hacker News](https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html) — primary reporting, timeline, Microsoft response
- [Microsoft's agent-framework Hijacked on PyPI via Silent .pth Startup Hook — JFrog Security Research](https://research.jfrog.com/post/agent-framework-hijack/) — primary technical analysis, file hashes, payload behavior, env-var/file targeting, XRAY-1167986
- [Malicious code in agent-framework (PyPI) — GHSA-764m-3ppc-5m73 — GitHub Advisory Database](https://github.com/advisories/GHSA-764m-3ppc-5m73) — advisory, OpenSSF MAL-2026-20101, CWE-506, wheel hashes
- [Microsoft agent-framework PyPI Package Compromised — StepSecurity](https://www.stepsecurity.io/blog/microsoft-agent-framework-pypi-package-compromised) — detailed timeline with UTC timestamps, publisher anomalies, detection guidance
- [Microsoft agent-framework Compromised: Credential Stealer Targets Azure and CI Pipelines — Wiz](https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi) — cloud credential targeting analysis, managed identity impact
- [Agent Framework PyPI Package Compromised with Credential Stealer — Socket](https://socket.dev/blog/agent-framework-pypi-package-compromised-with-credential-stealer) — v1.26.2 evasion analysis, noting `__init__.py` restored to clean content
- [Microsoft Agent Framework Releases Poisoned With Credential Stealer — SecurityWeek](https://www.securityweek.com/microsoft-agent-framework-releases-poisoned-with-credential-stealer/) — corroboration of scope, download figures, and incident timeline
- [Official Microsoft agent-framework PyPI package compromised — opensourcemalware.com](https://opensourcemalware.com/blog/agent-framework-pypi-compromised) — open-source malware tracking entry

---
*Report generated by Actioner (REVISED — critic fixes applied: Sigma Rule 4 CommandLine branch removed, YARA Rule 1 dead strings removed and duplicate meta keys renamed, IOC defanging standardized, ATT&CK T1070.004 corrected to T1070)*
