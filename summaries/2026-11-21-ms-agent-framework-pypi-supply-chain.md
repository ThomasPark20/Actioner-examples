# Technical Analysis Report: Microsoft Agent-Framework PyPI Supply Chain Attack (2026-11-21)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-11-21
Version: 1.0 (DRAFT)

## Executive Summary

On November 17, 2026, an attacker published two malicious versions (1.26.1 and 1.26.2) of Microsoft's official `agent-framework` Python package to the Python Package Index (PyPI). The compromised package, which sees approximately 190,000 downloads per month, contained a credential stealer that planted `.pth` files in Python's site-packages directory, ensuring execution on every Python interpreter startup -- including pip itself. The stealer harvested Azure CLI credentials, cloud managed-identity tokens, GitHub Actions OIDC tokens, and a broad range of developer credential files, exfiltrating them via HTTPS POST to `webhook[.]site`. Both malicious versions were published within a 33-minute window (approximately 20:35-21:08 UTC) and were quarantined by PyPI after disclosure on November 18, 2026. The initial access vector remains under investigation; it is unclear whether the attacker compromised a maintainer's PyPI credentials, a GitHub admin account, or the CI/CD publishing pipeline.

## Background: Microsoft Agent Framework

Microsoft Agent Framework is an official Microsoft Python package for building AI agents. Hosted at `github[.]com/microsoft/agent-framework` and published to PyPI under the `agent-framework` name, the package had two listed maintainers (`microsoft` and `vibiret`) and followed a weekly release cadence with version 1.26.0 released on November 12, 2026. The package did not use PyPI Trusted Publishing (attestation-based publishing), leaving it reliant on API token or password-based authentication for uploads. With approximately 190,000 monthly downloads, the package is widely used across enterprise AI development pipelines, CI/CD systems, and Azure-hosted workloads.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-11-12 | Version 1.26.0 (legitimate) published to PyPI |
| 2026-11-17 ~20:35 | Version 1.26.1 (malicious) published to PyPI |
| 2026-11-17 ~21:08 | Version 1.26.2 (malicious) published to PyPI, approximately 33 minutes after 1.26.1 |
| 2026-11-18 | Public disclosure; both versions quarantined by PyPI |
| 2026-11-20 | Microsoft made the `microsoft/agent-framework` and `microsoft/onnxruntime` GitHub repositories private during investigation |

## Root Cause: Supply Chain Compromise of PyPI Package Publishing

The precise initial access vector has not been confirmed publicly. The attacker obtained the ability to publish new versions of the `agent-framework` package on PyPI. Potential vectors include compromise of a maintainer's PyPI API token or credentials, compromise of a GitHub admin account with access to the CI/CD publishing workflow, or compromise of the automated release pipeline. Notably, the package was not published via PyPI Trusted Publishing, meaning no cryptographic attestation tied the upload to a specific GitHub Actions workflow. This gap would allow anyone with valid PyPI credentials to publish arbitrary versions.

## Technical Analysis of the Malicious Payload

### 1. Python .pth Startup Hook Injection

Both malicious versions exploit Python's `.pth` file mechanism to achieve automatic execution. When Python starts, it scans the site-packages directory for `.pth` files and executes any line beginning with `import`. This means the malicious code runs on every Python invocation -- including `pip install` itself, `pytest`, Django management commands, or any other Python-based tool -- without requiring the `agent-framework` package to be explicitly imported.

**Version 1.26.1** installs:
- `agent_framework_meta.pth` -- contains `import agent_framework_meta`, triggering the stealer module on every Python startup

**Version 1.26.2** installs:
- `af_runtime_diag.pth` -- contains `import af_runtime_diag`, triggering the revised stealer
- `af_runtime_diag.py` -- a new top-level module with expanded collection capabilities

### 2. Credential and Token Harvesting

The stealer performs broad credential harvesting across multiple categories:

**Environment variables:** Collected via substring-based matching of environment variable names, targeting cloud provider tokens, CI/CD secrets, and API keys.

**Credential files:**
- `~/.azure/*.json` (Azure CLI session tokens and configuration)
- `.npmrc` (npm registry authentication tokens)
- `pip.conf` (Python package index credentials)
- `~/.netrc` (generic network credentials)
- `~/.git-credentials` (Git credential store)
- `~/.docker/config.json` (Docker registry credentials)
- Hugging Face credentials
- Microsoft Azure DevOps agent credential files
- `.env` files and JSON configuration files

**Azure-specific token theft:**
- Azure managed identity tokens requested via `IDENTITY_ENDPOINT` or `MSI_ENDPOINT` (App Service/Functions), or via the IMDS endpoint at `169.254.169.254`
- Azure Instance Metadata Service (IMDS) instance metadata (up to 8,000 characters)

**GitHub Actions / Azure DevOps OIDC tokens (version 1.26.2):**
- Uses `SYSTEM_ACCESSTOKEN` and `SYSTEM_OIDCREQUESTURI` to request a federated token for `api://AzureADTokenExchange`
- This enables the attacker to obtain tokens that can authenticate to Azure resources configured to trust the compromised CI/CD identity

### 3. C2 Infrastructure

The exfiltration mechanism is straightforward:

1. Collected data is assembled into a JSON document
2. The JSON is zlib-compressed
3. The compressed data is Base64-encoded
4. An HTTPS POST sends the payload to: `hxxps://webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb`

The use of `webhook[.]site` -- a legitimate webhook testing service -- as the exfiltration endpoint allows the attacker to blend into normal developer traffic and avoid domain-reputation-based blocking, while providing easy access to stolen data through the webhook.site web interface.

### 4. Platform-Specific Behavior

#### All platforms (Linux, macOS, Windows)

The `.pth` hook mechanism is cross-platform and fires on any OS where the compromised wheel is installed. Credential file paths use OS-appropriate expansion (`~` resolves to `%USERPROFILE%` on Windows, `$HOME` on Unix).

#### Azure Cloud Environments

Additional collection targets Azure-specific infrastructure:
- App Service / Functions: queries `IDENTITY_ENDPOINT` / `MSI_ENDPOINT` for managed identity tokens
- Virtual Machines / VMSS: queries IMDS at `169.254.169.254` for instance metadata and access tokens
- Azure DevOps pipelines: requests OIDC federated tokens

### 5. Anti-Forensics / Evasion Techniques

- **Legitimate package name:** Uses the real, trusted `agent-framework` package name from a trusted publisher (Microsoft)
- **No code changes to package source:** The malicious content is in added files only, so diffing the Python source modules would not reveal the backdoor
- **Generic filenames:** `agent_framework_meta.pth` and `af_runtime_diag.py` appear to be legitimate package infrastructure
- **Compression and encoding:** Exfiltrated data is zlib-compressed and Base64-encoded, hindering content inspection by DLP/proxy systems
- **Legitimate exfiltration service:** `webhook[.]site` is a commonly-used developer tool, reducing the likelihood of domain-based blocking

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` replacing `https://`
> - Domains: `[.]` replacing dots

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `agent-framework` (PyPI) | 1.26.1 | Initial malicious version with .pth credential stealer |
| `agent-framework` (PyPI) | 1.26.2 | Revised version adding OIDC token theft and broader env-var harvesting |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| All | `<site-packages>/agent_framework_meta.pth` | v1.26.1 startup hook; contains `import agent_framework_meta` |
| All | `<site-packages>/af_runtime_diag.pth` | v1.26.2 startup hook; contains `import af_runtime_diag` |
| All | `<site-packages>/af_runtime_diag.py` | v1.26.2 credential stealer module |

Note: No SHA256 hashes for the malicious wheel files have been published in the sources available at the time of this report. The malicious versions have been quarantined on PyPI and are no longer available for download.

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `webhook[.]site` | Exfiltration endpoint (legitimate testing service abused by attacker) |
| URL | `hxxps://webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb` | Specific exfiltration endpoint receiving stolen credentials |
| IP | `169.254.169[.]254` | Azure IMDS endpoint queried by stealer for managed identity tokens (not attacker-controlled) |

### Behavioral

- Python process creating `.pth` files in site-packages with names `agent_framework_meta.pth` or `af_runtime_diag.pth`
- Python process reading multiple credential files (`~/.azure/*.json`, `.npmrc`, `.netrc`, `.git-credentials`, `.docker/config.json`) in rapid succession
- Python process making HTTPS POST requests to `webhook[.]site` with Base64-encoded payloads
- Python process querying Azure IMDS at `169.254.169.254` for access tokens
- Environment variables `SYSTEM_ACCESSTOKEN` and `SYSTEM_OIDCREQUESTURI` being accessed by unexpected Python processes

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Attacker published malicious versions of a legitimate Microsoft package on PyPI |
| T1059.006 | Command and Scripting Interpreter: Python | Payload executes as Python code via .pth import hook mechanism |
| T1546.016 | Event Triggered Execution: Installer Packages | .pth files in site-packages trigger execution on every Python interpreter startup |
| T1555 | Credentials from Password Stores | Harvests credentials from Azure CLI, Docker, npm, pip, git, and Hugging Face credential stores |
| T1552.001 | Unsecured Credentials: Credentials In Files | Reads credential files from well-known paths (~/.azure/, .npmrc, .netrc, .git-credentials, .docker/config.json) |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Queries Azure IMDS (169.254.169.254) for managed identity tokens |
| T1041 | Exfiltration Over C2 Channel | Stolen data POSTed to webhook.site via HTTPS |
| T1027 | Obfuscated Files or Information | Exfiltrated data is zlib-compressed and Base64-encoded |

## Impact Assessment

**Breadth:** The `agent-framework` package receives approximately 190,000 downloads per month. The exposure window was approximately 24 hours (November 17-18, 2026). Any environment that ran `pip install` with unconstrained version resolution during this window, or that had `agent-framework>=1.26.0` in requirements, could have installed a malicious version. CI/CD pipelines without pinned dependencies are especially at risk.

**Depth:** The stealer provides broad credential access including Azure managed identity tokens, Azure DevOps OIDC federation tokens, and developer credential files. Compromised OIDC tokens could allow lateral movement into Azure resources. Compromised Azure CLI tokens provide direct access to Azure subscriptions. The scope of downstream compromise depends on the privileges of the stolen credentials.

**Stealth:** The `.pth` hook mechanism is subtle -- the malicious code runs on Python startup before any application code, leaves no process tree indicators, and the filenames mimic legitimate package infrastructure. Without file-integrity monitoring on site-packages, the compromise would not be visible in normal application logs.

## Detection & Remediation

### Immediate Detection

Check for the presence of malicious files:

```bash
# Search all Python environments for malicious .pth files
find / -name "agent_framework_meta.pth" -o -name "af_runtime_diag.pth" -o -name "af_runtime_diag.py" 2>/dev/null

# Check installed version
pip show agent-framework 2>/dev/null | grep -E "^Version:"

# Search pip install logs for malicious versions
grep -r "agent-framework-1.26.[12]" /var/log/ ~/.pip/ 2>/dev/null

# Search DNS/proxy logs for the exfiltration endpoint
# (organization-specific log search for webhook.site and the UUID d381fd80-ec62-42ad-8f5c-d1b15103c9bb)
```

### Remediation

1. **Isolate** affected hosts and CI runners immediately
2. **Pin** to version 1.26.0 in all requirements files and rebuild environments from clean state: `agent-framework==1.26.0`
3. **Remove** malicious files if found: `agent_framework_meta.pth`, `af_runtime_diag.pth`, `af_runtime_diag.py` from site-packages
4. **Search** proxy/DNS logs for requests to `webhook.site` (specifically the UUID `d381fd80-ec62-42ad-8f5c-d1b15103c9bb`)
5. **Rotate** all credentials that may have been exposed, from a clean system:
   - Azure CLI credentials (`az login` from clean environment)
   - Azure managed identity keys (rotate if possible, review access logs)
   - npm tokens (regenerate in npm registry)
   - Git credentials (regenerate personal access tokens)
   - Docker registry credentials
   - Any secrets stored in `.env` files
   - Hugging Face API tokens
6. **Audit** Azure AD sign-in and activity logs for use of stolen tokens
7. **Audit** GitHub Actions workflow runs for unexpected OIDC token requests
8. **Review** Azure DevOps service connections that use federated credentials

### Long-Term Hardening

- **Enable PyPI Trusted Publishing** for all organizational packages to tie uploads cryptographically to specific CI/CD workflows
- **Pin dependency versions** in all requirements files and lock files; never allow unconstrained minor/patch version resolution in production or CI
- **Use hash verification** (`pip install --require-hashes`) to prevent installation of unexpected package content
- **Monitor site-packages** for unexpected `.pth` files using file-integrity monitoring
- **Deploy egress filtering** to block or alert on outbound connections to `webhook.site` and similar testing services from production environments
- **Implement dependency scanning** in CI/CD to detect known-malicious package versions

## Detection Rules

Seven Sigma rules, three YARA rules, and two Suricata rules cover the file-system artifacts (malicious .pth hooks and stealer module), network indicators (C2 exfiltration to webhook.site), behavioral patterns (credential file access and Azure IMDS queries by Python), and package content (strings characteristic of the stealer payload). The webhook.site DNS rule may produce false positives in developer environments where webhook.site is used for legitimate testing.

### Sigma: Malicious .pth File Creation

Detects creation of the attack-specific `.pth` startup hook files in site-packages.

compile: splunk/logscale pass | confidence: high

```yaml
title: Malicious PTH File From Microsoft Agent-Framework Supply Chain Attack
id: 7a3c1d4e-9f2b-4e8a-b6c5-d1e0f3a2b7c9
status: experimental
description: >
    Detects the creation of malicious .pth files associated with the compromised
    Microsoft agent-framework PyPI package (versions 1.26.1 and 1.26.2). The attack
    plants .pth files in site-packages that execute credential-stealing code on every
    Python interpreter startup.
references:
    - https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html
author: Actioner
date: 2026/11/21
tags:
    - attack.t1195.001
    - attack.t1546.016
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '\agent_framework_meta.pth'
            - '/agent_framework_meta.pth'
            - '\af_runtime_diag.pth'
            - '/af_runtime_diag.pth'
    condition: selection
falsepositives:
    - None expected. These file names are unique to the malicious payload.
level: critical
```

<!-- audit: sigma check crashed on MITRE ATT&CK data fetch (HTTP 403 from proxy, not a rule issue); sigma convert --without-pipeline -t splunk and -t log_scale both produced valid output. T1546.016 maps to .pth as installer-package triggered execution. No defanged values in detection fields. -->

### Sigma: af_runtime_diag.py Stealer Module Creation

Detects creation of the v1.26.2 stealer module in a site-packages directory.

compile: splunk/logscale pass | confidence: high

```yaml
title: Malicious af_runtime_diag Module From Agent-Framework Compromise
id: 8b4d2e5f-a0c3-4f9b-c7d6-e2f1a4b3c8da
status: experimental
description: >
    Detects the creation of the af_runtime_diag.py module dropped by version 1.26.2
    of the compromised Microsoft agent-framework PyPI package. This module collects
    GitHub Actions OIDC tokens and broadens credential harvesting when imported via
    the companion .pth startup hook.
references:
    - https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html
author: Actioner
date: 2026/11/21
tags:
    - attack.t1195.001
    - attack.t1059.006
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '\af_runtime_diag.py'
            - '/af_runtime_diag.py'
    selection_path:
        TargetFilename|contains:
            - 'site-packages'
    condition: selection and selection_path
falsepositives:
    - None expected. This filename in a site-packages directory is specific to the malicious payload.
level: critical
```

<!-- audit: sigma convert pass for splunk and log_scale. Scoped to site-packages to reduce FP from unrelated files named af_runtime_diag.py. -->

### Sigma: DNS Query to webhook.site C2

Detects DNS resolution of the exfiltration service used by the stealer.

compile: splunk/logscale pass | confidence: medium

```yaml
title: DNS Query to Webhook.site C2 Used by Agent-Framework Credential Stealer
id: 9c5e3f6a-b1d4-4a0c-d8e7-f3a2b5c4d9eb
status: experimental
description: >
    Detects DNS resolution of webhook.site, the exfiltration endpoint used by the
    compromised Microsoft agent-framework PyPI package (versions 1.26.1 and 1.26.2).
    Stolen credentials are zlib-compressed, Base64-encoded, and POSTed to a specific
    webhook.site URL.
references:
    - https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html
author: Actioner
date: 2026/11/21
tags:
    - attack.t1195.001
    - attack.t1041
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'webhook.site'
    condition: selection
falsepositives:
    - Legitimate developer testing using webhook.site for webhook debugging. Investigate in context of Python process and agent-framework installation.
level: medium
```

<!-- audit: sigma convert pass. Level medium due to legitimate use of webhook.site by developers. Best deployed with correlation to Python process context. -->

### Sigma: HTTP POST to Specific webhook.site Exfiltration UUID

Detects the exact exfiltration endpoint in proxy logs.

compile: splunk/logscale pass | confidence: high

```yaml
title: HTTP POST to Webhook.site C2 Endpoint Used by Agent-Framework Stealer
id: ad6f4a7b-c2e5-4b1d-e9f8-a4b3c6d5eafc
status: experimental
description: >
    Detects HTTPS POST requests to the specific webhook.site endpoint used for
    credential exfiltration by the compromised Microsoft agent-framework PyPI package.
    The payload is zlib-compressed and Base64-encoded stolen credentials and tokens.
references:
    - https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html
author: Actioner
date: 2026/11/21
tags:
    - attack.t1195.001
    - attack.t1041
logsource:
    category: proxy
detection:
    selection:
        cs-method: 'POST'
        r-dns|contains: 'webhook.site'
        cs-uri-stem|contains: '/d381fd80-ec62-42ad-8f5c-d1b15103c9bb'
    condition: selection
falsepositives:
    - None expected. The UUID path is unique to this attack campaign.
level: critical
```

<!-- audit: sigma convert pass. UUID is campaign-specific. Real value used (not defanged) per logsource-encoding spec. -->

### Sigma: Python Process Accessing Multiple Credential Files

Detects the credential harvesting file access pattern.

compile: splunk/logscale pass | confidence: medium

```yaml
title: Suspicious Credential File Access by Python Process Matching Agent-Framework Stealer Pattern
id: be7a5b8c-d3f6-4c2e-fab9-b5c4d7e6fbad
status: experimental
description: >
    Detects Python processes accessing multiple credential files matching the pattern
    used by the compromised Microsoft agent-framework package. The stealer harvests
    Azure CLI credentials, .npmrc, pip.conf, .netrc, .git-credentials, Docker config,
    and Hugging Face tokens.
references:
    - https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html
author: Actioner
date: 2026/11/21
tags:
    - attack.t1555
    - attack.t1552.001
logsource:
    category: file_event
detection:
    selection_process:
        Image|endswith:
            - '/python'
            - '/python3'
            - '\python.exe'
            - '\python3.exe'
    selection_files:
        TargetFilename|contains:
            - '.azure/'
            - '.npmrc'
            - '.netrc'
            - '.git-credentials'
            - '.docker/config.json'
    condition: selection_process and selection_files
falsepositives:
    - Legitimate Python-based CI/CD tooling or configuration management scripts that read these files. Correlate with pip install activity of agent-framework.
level: high
```

<!-- audit: sigma convert pass. Behavioral rule matching Python reading credential files. Medium confidence due to potential legitimate CI/CD tools reading subsets of these files. -->

### Sigma: Python Process Querying Azure IMDS

Detects Python querying Azure IMDS for managed identity tokens.

compile: splunk/logscale pass | confidence: medium

```yaml
title: Python Process Querying Azure IMDS Matching Agent-Framework Stealer Pattern
id: cf8b6c9d-e4a7-4d3f-abc0-c6d5e8f7acbe
status: experimental
description: >
    Detects a Python process making HTTP connections to the Azure Instance Metadata
    Service (169.254.169.254) to steal managed identity tokens, as performed by the
    compromised Microsoft agent-framework package.
references:
    - https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html
author: Actioner
date: 2026/11/21
tags:
    - attack.t1552.005
    - attack.t1195.001
logsource:
    category: network_connection
detection:
    selection:
        Image|endswith:
            - '/python'
            - '/python3'
            - '\python.exe'
            - '\python3.exe'
        DestinationIp: '169.254.169.254'
    condition: selection
falsepositives:
    - Legitimate Python applications running on Azure that query IMDS for instance metadata or managed identity tokens. Correlate with agent-framework package presence.
level: medium
```

<!-- audit: sigma convert pass. Level medium because legitimate Azure SDKs in Python query IMDS. Best as a contextual signal in combination with other IOCs. -->

### Sigma: pip Install of Malicious Package Versions

Detects command-line installation of the specific malicious versions.

compile: splunk/logscale pass | confidence: high

```yaml
title: Installation of Compromised Microsoft Agent-Framework Package Versions
id: da9c7dae-f5b8-4e4a-bcd1-d7e6f9a8bdcf
status: experimental
description: >
    Detects pip install commands targeting the malicious versions 1.26.1 or 1.26.2
    of the Microsoft agent-framework PyPI package. These versions contain a credential
    stealer that runs on every Python interpreter startup.
references:
    - https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html
author: Actioner
date: 2026/11/21
tags:
    - attack.t1195.001
    - attack.t1059.006
logsource:
    category: process_creation
detection:
    selection_pip:
        CommandLine|contains:
            - 'pip install'
            - 'pip3 install'
    selection_package:
        CommandLine|contains:
            - 'agent-framework==1.26.1'
            - 'agent-framework==1.26.2'
            - 'agent_framework==1.26.1'
            - 'agent_framework==1.26.2'
    condition: selection_pip and selection_package
falsepositives:
    - None expected. These specific versions are known malicious.
level: critical
```

<!-- audit: sigma convert pass. Only fires on explicit pinned install of malicious versions. Will miss unpinned installs that resolved to 1.26.1/1.26.2 during the exposure window. -->

### YARA: .pth Hook Files, Credential Stealer Module, Malicious Wheel

Three YARA rules detect: (1) the small .pth startup hook files by their import lines, (2) the credential stealer module by the combination of C2 URL, Azure token theft strings, and credential file paths, and (3) the malicious wheel archive by the combination of ZIP header, .pth filenames, and campaign markers.

compile: yarac pass (exit 0) | confidence: high

```yara
rule Supply_Chain_MS_Agent_Framework_PTH_Hook
{
    meta:
        description = "Detects malicious .pth startup hook files from compromised Microsoft agent-framework PyPI package (versions 1.26.1, 1.26.2)"
        author = "Actioner"
        date = "2026-11-21"
        reference = "https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pth1 = "import agent_framework_meta" ascii
        $pth2 = "import af_runtime_diag" ascii

    condition:
        filesize < 1KB and
        any of ($pth*)
}

rule Supply_Chain_MS_Agent_Framework_Credential_Stealer
{
    meta:
        description = "Detects the credential stealer payload from the compromised Microsoft agent-framework PyPI package. Matches characteristic strings from the stealer module."
        author = "Actioner"
        date = "2026-11-21"
        reference = "https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $c2 = "webhook.site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb" ascii wide
        $azure1 = ".azure/" ascii
        $azure2 = "IDENTITY_ENDPOINT" ascii
        $azure3 = "MSI_ENDPOINT" ascii
        $azure4 = "169.254.169.254" ascii
        $oidc1 = "SYSTEM_ACCESSTOKEN" ascii
        $oidc2 = "SYSTEM_OIDCREQUESTURI" ascii
        $oidc3 = "AzureADTokenExchange" ascii
        $cred1 = ".npmrc" ascii
        $cred2 = "pip.conf" ascii
        $cred3 = ".netrc" ascii
        $cred4 = ".git-credentials" ascii
        $cred5 = ".docker/config.json" ascii
        $func1 = "zlib" ascii
        $func2 = "base64" ascii

    condition:
        filesize < 500KB and
        $c2 and
        (2 of ($azure*) or 2 of ($oidc*)) and
        2 of ($cred*) and
        all of ($func*)
}

rule Supply_Chain_MS_Agent_Framework_Malicious_Wheel
{
    meta:
        description = "Detects malicious Python wheel files from the compromised Microsoft agent-framework package by matching the combination of .pth hook filenames and exfiltration endpoint"
        author = "Actioner"
        date = "2026-11-21"
        reference = "https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $zip_magic = { 50 4B 03 04 }
        $pth1 = "agent_framework_meta.pth" ascii
        $pth2 = "af_runtime_diag.pth" ascii
        $c2 = "webhook.site" ascii
        $ver1 = "1.26.1" ascii
        $ver2 = "1.26.2" ascii

    condition:
        $zip_magic at 0 and
        (1 of ($pth*)) and
        ($c2 or 1 of ($ver*))
}
```

<!-- audit: yarac compiled all three rules successfully (exit code 0). PTH_Hook rule uses filesize < 1KB to scope to the tiny .pth files. Credential_Stealer requires C2 URL as anchor. Malicious_Wheel requires ZIP magic at offset 0. -->

### Suricata: C2 Exfiltration and DNS

Two Suricata rules detect the HTTPS POST exfiltration to the specific webhook.site UUID endpoint and DNS lookups to webhook.site.

compile: suricata -T pass ("Configuration provided was successfully loaded") | confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SUPPLY-CHAIN Microsoft agent-framework credential exfiltration to webhook.site"; flow:established,to_server; http.method; content:"POST"; http.host; content:"webhook.site"; http.uri; content:"/d381fd80-ec62-42ad-8f5c-d1b15103c9bb"; reference:url,thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html; classtype:trojan-activity; sid:2026111801; rev:1;)

alert dns $HOME_NET any -> any any (msg:"SUPPLY-CHAIN DNS query to webhook.site potential agent-framework C2"; dns.query; content:"webhook.site"; nocase; reference:url,thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html; classtype:trojan-activity; sid:2026111802; rev:1;)
```

<!-- audit: suricata -T -S validated successfully. HTTP rule requires TLS inspection/decryption to match http.host and http.uri on HTTPS traffic. DNS rule will match in cleartext DNS; DoH/DoT bypass possible. -->

## Lessons Learned

1. **Trusted Publishing is not optional.** The `agent-framework` package did not use PyPI Trusted Publishing, which would have cryptographically tied uploads to a specific GitHub Actions workflow and repository. Had it been enabled, the attacker would have needed to compromise the GitHub Actions workflow itself, not just PyPI credentials.

2. **The `.pth` mechanism is a powerful persistence vector.** Python's `.pth` file feature, designed for path configuration, allows arbitrary code execution on every interpreter startup. This is a known class of attack (also exploited in the May 2026 `durabletask` / TeamPCP incident) and yet remains undermonitored. Organizations should monitor site-packages directories for new `.pth` files via file integrity monitoring.

3. **Pin and hash dependencies.** Unconstrained version resolution (`agent-framework>=1.26.0` or bare `agent-framework`) automatically installed the malicious version. Using `pip install --require-hashes` with a lockfile would have prevented installation of any package content that did not match known-good hashes.

4. **Supply chain attacks against high-download packages have outsized impact.** At 190,000 downloads/month, even a 24-hour exposure window means thousands of potential victims, particularly automated CI/CD pipelines that install dependencies on every run.

5. **Webhook testing services as C2 infrastructure.** Services like `webhook.site` provide free, anonymous data-collection endpoints that blend into developer traffic. Network policies should restrict or monitor outbound access to such services, especially from production and CI/CD environments.

## Sources

- [The Hacker News: Attackers Compromise Microsoft's Agent Framework](https://thehackernews.com/2026/11/attackers-compromise-microsofts-agent.html) -- primary source for technical details, timeline, IOCs, and remediation guidance
- [PyPI: agent-framework Package](https://pypi.org/project/agent-framework/) -- package metadata, release history, and maintainer information

---
*Report generated by Actioner*
