# Technical Analysis Report: LiteLLM 1.107.0 Supply Chain Compromise (2026-10-29)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-29
Version: 1.0

## Executive Summary

On October 23, 2026, Microsoft Security Research published a detailed analysis of a supply chain compromise affecting LiteLLM version 1.107.0, a widely-used Python proxy for LLM API calls. The attacker injected malicious Python startup hooks (`.pth` and `sitecustomize.py` files) into the official PyPI distribution wheels, enabling automatic credential theft every time a Python interpreter started in an environment where the compromised package was installed. The payload collected AI/IDE configurations, cloud provider credentials, browser credential databases, SSH keys, GPG keys, Git credentials, and the LiteLLM proxy's own stored API keys, then exfiltrated them via AES-256-CBC encrypted HTTP POST requests to attacker-controlled infrastructure at www[.]litellm[.]dev.

This incident is distinct from the earlier LiteLLM CVE-2026-42271 RCE vulnerability (June 2026) and the August 2026 LiteLLM/Trivy supply chain incidents. The exposure window, compromised wheel hashes, and exfiltration infrastructure are all unique to this October 2026 event. Any environment that installed `litellm==1.107.0` from PyPI during the exposure window should be considered fully compromised and must undergo immediate secret rotation.

## Background: LiteLLM

LiteLLM is an open-source Python library and proxy server that provides a unified interface to over 100 LLM providers (OpenAI, Azure, AWS Bedrock, Google Vertex AI, Anthropic, and others). It is used extensively in AI/ML pipelines, development environments, and production proxy deployments to manage API key routing and rate limiting. Its position as a credential broker for multiple cloud AI services makes it a high-value supply chain target: a single compromise yields access to every upstream API key the proxy manages, plus the host environment's broader credential surface.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2026-10-20 (est.) | Attacker gains access to the LiteLLM PyPI publishing pipeline |
| ~2026-10-20 (est.) | Malicious version 1.107.0 wheels published to PyPI containing cook.pth, cook.py, and sitecustomize.py |
| 2026-10-23 | Microsoft Security Research publishes detailed technical analysis |
| 2026-10-23 | Compromised version pulled from PyPI |
| 2026-10-26 | The Register publishes additional reporting on the initial access vector (exposed master key) |

## Root Cause: Supply Chain Injection via Python Startup Hooks

The attacker compromised the LiteLLM build/publish pipeline and injected three malicious files into the distributed wheel archives. Python's `.pth` file mechanism causes `cook.pth` to execute code at interpreter startup (before any user code runs), which loads `cook.py`. A secondary persistence mechanism via `sitecustomize.py` ensures execution even if `.pth` processing is disabled. This leverages a legitimate Python feature (T1546 -- Event Triggered Execution) as an execution vector, making it invisible to standard application-level monitoring. The Hacker News reported that the initial access to the publishing pipeline started with a leaked LiteLLM master key.

## Technical Analysis of the Malicious Payload

### 1. Startup Hook Injection (cook.pth / sitecustomize.py)

The compromised wheels contained three files planted in the Python `site-packages` directory:

- **cook.pth** -- A `.pth` file containing an `import` statement that triggers `cook.py` at Python interpreter startup. Python processes `.pth` files in `site-packages` automatically during initialization.
- **cook.py** -- The primary credential-stealing payload (~500KB), containing the full collection, encryption, and exfiltration logic.
- **sitecustomize.py** -- A fallback loader that duplicates the `cook.pth` trigger mechanism via Python's `sitecustomize` import hook, providing redundant execution.

Platform-specific variants existed for Linux/macOS (Unix paths, procfs access) and Windows (registry paths, AppData locations).

**Compromised wheel SHA-256 hashes:**

| Platform | SHA-256 |
|----------|---------|
| macOS x86_64 | `7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d` |
| macOS arm64 | `0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a` |
| manylinux aarch64 | `668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6` |
| manylinux x86_64 | `462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7` |
| musllinux aarch64 | `c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054` |
| musllinux x86_64 | `1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00` |
| Windows amd64 | `12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484` |

### 2. Credential Collection Engine

Upon execution, cook.py first checks for the `PRIVCOLLECT_ACTIVE` environment variable as a re-entrance guard (to prevent recursive execution when spawning subprocesses). If not set, it sets the variable and proceeds with a comprehensive credential harvesting sweep targeting:

- **AI/IDE configurations:** GitHub Copilot config, MCP (Model Context Protocol) config files, VS Code settings
- **Git credentials:** `.gitconfig`, credential helpers, `.git-credentials`
- **Environment files:** `.env`, `.env.local`, and other dotenv files throughout the filesystem
- **Private keys:** SSH keys (`~/.ssh/`), GPG keys
- **Cloud provider credentials:**
  - AWS: `~/.aws/credentials`, `~/.aws/config`
  - Azure: `~/.azure/`, token caches
  - GCP: `~/.config/gcloud/`, application default credentials
- **Container/orchestration secrets:** Kubernetes `~/.kube/config`, Docker `~/.docker/config.json`
- **Browser credential databases:** Chromium-based and Firefox Login Data / key databases
- **LiteLLM proxy internals:** Direct SQLite/database queries against `LiteLLM_CredentialsTable` and `LiteLLM_ProxyModelTable` to extract all stored API keys
- **Process environments:** Enumeration of `/proc/*/environ` (Linux) to capture runtime secrets from all accessible processes

The marker file `/tmp/.pc_once_72129118c59f5636c0bb` prevents repeated collection on the same host.

### 3. C2 Infrastructure

The attack used a multi-stage C2 architecture:

- **Dead-drop resolver:** The payload first fetched `hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt` to retrieve the current exfiltration domain, providing the attacker with domain-rotation capability.
- **Exfiltration endpoint:** `hxxp://www[.]litellm[.]dev/healthcheck` -- an HTTP (not HTTPS) POST endpoint disguised as a health check. The domain `litellm[.]dev` is attacker-controlled infrastructure impersonating the legitimate LiteLLM project.
- **Remote code loader:** A secondary endpoint at `/codepy` on the exfiltration domain served additional Python code, loaded via a mechanism gated by `/tmp/remote_code_loader.lock`.
- **User-Agent:** A fixed browser-like User-Agent string to blend with normal web traffic.

### 4. Platform-Specific Behavior

#### Linux / macOS

- Credential paths follow Unix conventions (`~/.ssh/`, `~/.aws/`, etc.)
- Process environment harvesting via `/proc/*/environ` (procfs)
- Staging directories in `/tmp/.pc_e_*` for OpenSSL operations
- Marker files in `/tmp/.pc_once_*` and `/tmp/.pc_*`

#### Windows

- Credential paths use `%APPDATA%`, `%LOCALAPPDATA%`, `%USERPROFILE%` locations
- Browser credential databases in Windows-specific Chrome/Edge/Firefox paths
- Separate cook.py and sitecustomize.py variants with Windows-specific SHA-256 hashes
- Temp staging in `%TEMP%` instead of `/tmp`

### 5. Anti-Forensics / Evasion Techniques

- **Encrypted exfiltration:** AES-256-CBC encryption with a per-run random 32-byte key and 16-byte IV, wrapped by a 4096-bit RSA public key (OAEP SHA-256). This means network captures cannot be decrypted without the attacker's private key.
- **Legitimate-looking traffic:** HTTP POST to `/healthcheck` with `application/octet-stream` Content-Type mimics health monitoring traffic.
- **Re-entrance guard:** The `PRIVCOLLECT_ACTIVE` environment variable prevents double-execution and noisy repeated activity.
- **Once-marker:** The `/tmp/.pc_once_72129118c59f5636c0bb` file prevents re-collection on the same host, reducing detection opportunities.
- **Dead-drop domain resolution:** Using a GitHub raw URL for domain configuration allows the attacker to rotate exfiltration infrastructure without modifying the payload.
- **Encrypted key transport:** The RSA-wrapped AES key (in `key.bin`) alongside the encrypted data (`data.bin`) and metadata (`hdr.json`) are bundled as a gzip tar archive before HTTP POST, making the exfiltrated data appear as a generic binary blob.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| litellm | 1.107.0 | Compromised PyPI wheels with credential-stealing startup hooks |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux/macOS | site-packages/cook.py | `9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25` | Primary credential stealer |
| Windows | site-packages/cook.py | `03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea` | Windows variant of credential stealer |
| Linux/macOS | site-packages/sitecustomize.py | `34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa` | Fallback startup hook loader |
| Windows | site-packages/sitecustomize.py | `b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465` | Windows fallback loader |
| All | site-packages/cook.pth | `7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb` | Python startup trigger |
| All | site-packages/cook.pth | `84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d` | cook.pth variant |
| Linux/macOS | /tmp/remote_code_loader.lock | -- | Remote code loader mutex |
| Linux/macOS | /tmp/.pc_once_72129118c59f5636c0bb | -- | Once-execution marker |
| Linux/macOS | /tmp/.pc_e_* | -- | OpenSSL staging directories |
| Linux/macOS | /tmp/.pc_* | -- | RSA key wrapping staging |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | www[.]litellm[.]dev | Exfiltration / C2 domain |
| URL | hxxp://www[.]litellm[.]dev/healthcheck | Credential exfiltration endpoint (HTTP POST) |
| URL | hxxps://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt | Dead-drop domain resolver |
| URL | /codepy (on exfil domain) | Remote code loader endpoint |

### Behavioral

- Python processes spawning with `PRIVCOLLECT_ACTIVE` environment variable set
- Python `-c` one-liners querying `LiteLLM_CredentialsTable` or `LiteLLM_ProxyModelTable`
- OpenSSL commands referencing `/tmp/.pc_e_*` staging paths
- HTTP POST to `/healthcheck` with `application/octet-stream` Content-Type and `X-SHA256` header
- File creation of `cook.pth`, `cook.py`, or `sitecustomize.py` in Python site-packages
- DNS queries for `litellm[.]dev`
- Outbound HTTP to GitHub raw content (`raw[.]githubusercontent[.]com/letters9813/`)

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Malicious code injected into LiteLLM 1.107.0 PyPI wheels |
| T1546 | Event Triggered Execution | cook.pth and sitecustomize.py execute at Python startup (.pth file abuse is not yet cataloged as an ATT&CK sub-technique) |
| T1059.006 | Command and Scripting Interpreter: Python | Python used as the execution environment for the payload |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | AES-256-CBC encryption of exfiltrated data |
| T1560.001 | Archive Collected Data: Archive via Utility | Harvested credentials bundled as gzip tar archive (hdr.json, data.bin, key.bin) before exfiltration |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvesting .env, .aws/credentials, .gitconfig, etc. |
| T1552.004 | Unsecured Credentials: Private Keys | Collection of SSH keys, GPG keys |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chromium/Firefox credential database extraction |
| T1082 | System Information Discovery | Host enumeration during collection |
| T1016 | System Network Configuration Discovery | Network information gathered alongside credentials |
| T1005 | Data from Local System | Comprehensive local file collection |
| T1102.001 | Web Service: Dead Drop Resolver | GitHub raw URL for domain configuration |
| T1105 | Ingress Tool Transfer | Remote code loader fetching additional payloads |

## Impact Assessment

**Breadth:** Any organization or developer that installed `litellm==1.107.0` from PyPI during the exposure window is affected. Given LiteLLM's popularity in AI/ML workflows, the blast radius spans production proxy deployments, CI/CD pipelines, developer workstations, and containerized environments.

**Depth:** The payload harvests the broadest possible credential surface -- from cloud provider keys (AWS, Azure, GCP) to browser passwords, SSH keys, and the LiteLLM proxy's own stored API keys. A compromised LiteLLM proxy effectively grants access to every upstream LLM provider it manages.

**Stealth:** The use of Python startup hooks means the payload executes silently on every Python invocation without any user action. The once-marker and re-entrance guard minimize repeated network activity, and the encrypted exfiltration blends with health-check traffic.

## Detection & Remediation

### Immediate Detection

```bash
# Check if litellm 1.107.0 is installed
pip show litellm 2>/dev/null | grep -i "version: 1.107.0"

# Check for malicious files in any Python site-packages
find / -path "*/site-packages/cook.pth" -o -path "*/site-packages/cook.py" 2>/dev/null

# Check for staging artifacts
ls -la /tmp/.pc_once_72129118c59f5636c0bb 2>/dev/null
ls -la /tmp/remote_code_loader.lock 2>/dev/null
ls -lad /tmp/.pc_e_* 2>/dev/null
ls -lad /tmp/.pc_* 2>/dev/null

# Check for the environment variable in running processes
grep -r "PRIVCOLLECT_ACTIVE" /proc/*/environ 2>/dev/null

# Check SHA-256 of installed wheel files
pip cache list litellm 2>/dev/null

# Search DNS/proxy logs for the exfil domain
# (adapt to your log platform)
# grep "litellm.dev" /var/log/dns/*.log
```

### Remediation

1. **Containment:** Immediately uninstall `litellm==1.107.0` from all environments: `pip uninstall litellm && pip install litellm==1.106.0` (or the latest known-clean version).
2. **Eradication:** Remove all malicious artifacts:
   - Delete `cook.pth`, `cook.py`, `sitecustomize.py` from all Python site-packages directories
   - Remove `/tmp/remote_code_loader.lock`, `/tmp/.pc_once_*`, `/tmp/.pc_e_*`, `/tmp/.pc_*`
3. **Secret rotation (CRITICAL):** Assume all credentials on affected hosts are compromised:
   - Rotate all AWS, Azure, GCP access keys and service account credentials
   - Rotate all LiteLLM proxy API keys (upstream provider keys stored in LiteLLM_CredentialsTable)
   - Rotate GitHub tokens, SSH keys, GPG keys
   - Change browser-stored passwords
   - Rotate Kubernetes service account tokens and kubeconfig credentials
   - Rotate Docker registry credentials
   - Invalidate and re-issue all `.env` secrets
4. **Audit:** Review logs for outbound connections to `litellm[.]dev` or `raw[.]githubusercontent[.]com/letters9813/` to confirm exfiltration occurred.
5. **Container images:** Rebuild any container images that included `litellm==1.107.0`.

### Long-Term Hardening

- Pin Python package versions with hash verification (`pip install --require-hashes`)
- Use a private PyPI mirror with package scanning (e.g., Artifactory, Nexus with vulnerability policies)
- Monitor for unexpected `.pth` file creation in Python site-packages directories
- Implement outbound network monitoring for unexpected domains from Python-heavy environments
- Use virtual environment isolation with integrity monitoring for `.pth` files; consider `.pth` file allowlisting in hardened environments
- Deploy endpoint detection for the specific behavioral indicators (PRIVCOLLECT_ACTIVE, .pc_e_ staging)

## Detection Rules

Five Sigma rules, two Suricata rules, three YARA rules, and two Snort rules cover the filesystem artifacts, process-level behaviors, and network exfiltration patterns of this supply chain compromise. All rules were validated against their respective compilers (sigma convert, suricata -T, yarac); Snort rules are structural only as Snort is not installed in the validation environment.

### Sigma: Malicious Python Startup Files in Site-Packages

Detects creation of cook.pth or cook.py in Python site-packages directories.

<!-- revision: removed sitecustomize.py (legitimate Python mechanism used by coverage, instrumentation tools); downgraded confidence to medium -->

compile: pass (sigma convert splunk + logscale) | confidence: medium

```yaml
title: LiteLLM Supply Chain - Malicious Python Startup Files in Site-Packages
id: c3a7e1b2-4f8d-4e9a-b6c1-2d5f8a0e3b7c
status: experimental
description: >
    Detects creation of cook.pth or cook.py in Python site-packages directories,
    consistent with the LiteLLM 1.107.0 supply chain compromise that plants
    Python startup hooks for credential theft.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
author: Actioner
date: 2026-10-29
tags:
    - attack.t1195.001
    - attack.t1546
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains: 'site-packages'
        TargetFilename|endswith:
            - '\cook.pth'
            - '/cook.pth'
            - '\cook.py'
            - '/cook.py'
    condition: selection
falsepositives:
    - Development environments with custom .pth files named cook.pth (unlikely)
level: high
```

<!-- audit: validated via sigma convert --without-pipeline -t splunk and -t log_scale; sigma check blocked by proxy (MITRE ATT&CK data download 403); file_event category is cross-platform; TargetFilename uses both \ and / separators for Windows/Linux coverage -->

### Sigma: PRIVCOLLECT_ACTIVE Environment Variable

Detects processes launched with the PRIVCOLLECT_ACTIVE re-entrance guard environment variable visible on the command line.

<!-- revision: downgraded confidence to low and level to high; CommandLine|contains cannot capture env vars set programmatically via os.environ — requires EDR-specific telemetry beyond standard Sysmon to detect the env var in the process environment block -->

compile: pass (sigma convert splunk + logscale) | confidence: low

```yaml
title: LiteLLM Supply Chain - PRIVCOLLECT_ACTIVE Environment Variable
id: d4b8f2c3-5a9e-4f0b-c7d2-3e6a9b1f4c8d
status: experimental
description: >
    Detects processes launched with the PRIVCOLLECT_ACTIVE environment variable
    visible on the command line, used by the LiteLLM 1.107.0 malicious payload
    as a re-entrance guard during credential collection. Note: this rule only
    fires when the variable appears on the command line (e.g., env-prefixed
    invocations); the malware sets it via os.environ, which is not recorded
    by standard Sysmon EID 1 or Windows 4688 command-line auditing. Full
    coverage requires EDR telemetry that captures the process environment block.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
author: Actioner
date: 2026-10-29
tags:
    - attack.t1059.006
    - attack.t1552.001
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'PRIVCOLLECT_ACTIVE'
    condition: selection
falsepositives:
    - None known
level: high
```

<!-- audit: validated via sigma convert --without-pipeline -t splunk and -t log_scale; PRIVCOLLECT_ACTIVE is a unique string with no known legitimate use; CommandLine|contains will match env-prefixed commands and references in scripts but NOT os.environ-set variables; requires command-line auditing to be enabled (Sysmon EID 1 or Windows 4688 with command line); EDR-specific telemetry needed for full coverage -->

### Sigma: OpenSSL Staging in Temp Directories

Detects OpenSSL commands using the `.pc_e_` staging directory pattern for RSA key wrapping.

compile: pass (sigma convert splunk + logscale) | confidence: high

```yaml
title: LiteLLM Supply Chain - OpenSSL Staging in Temp Directories
id: e5c9a3d4-6b0f-4a1c-d8e3-4f7b0c2a5d9e
status: experimental
description: >
    Detects process creation involving OpenSSL commands referencing the .pc_e_
    staging directory pattern in /tmp, used by the LiteLLM 1.107.0 malicious
    payload for RSA key wrapping of exfiltrated credentials.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
author: Actioner
date: 2026-10-29
tags:
    - attack.t1027.013
    - attack.t1560.001
logsource:
    category: process_creation
detection:
    selection_openssl:
        CommandLine|contains: 'openssl'
    selection_staging:
        CommandLine|contains: '.pc_e_'
    condition: selection_openssl and selection_staging
falsepositives:
    - None known; the .pc_e_ directory naming pattern is specific to this malware
level: critical
```

<!-- audit: validated via sigma convert --without-pipeline -t splunk and -t log_scale; AND of openssl + .pc_e_ is highly specific; .pc_e_ prefix has no known legitimate use; requires process_creation logging with command lines -->

### Sigma: Python Database Credential Extraction

Detects Python one-liners querying LiteLLM proxy database tables for credential extraction.

compile: pass (sigma convert splunk + logscale) | confidence: high

```yaml
title: LiteLLM Supply Chain - Python Database Credential Extraction
id: f6d0b4e5-7c1a-4b2d-e9f4-5a8c1d3b6e0f
status: experimental
description: >
    Detects Python one-liner executions querying LiteLLM proxy database tables
    (LiteLLM_CredentialsTable or LiteLLM_ProxyModelTable), which indicates
    the credential harvesting stage of the LiteLLM 1.107.0 supply chain attack.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
author: Actioner
date: 2026-10-29
tags:
    - attack.t1059.006
    - attack.t1005
logsource:
    category: process_creation
detection:
    selection_python:
        Image|endswith:
            - '/python'
            - '/python3'
            - '\python.exe'
            - '\python3.exe'
        CommandLine|contains: '-c'
    selection_tables:
        CommandLine|contains:
            - 'LiteLLM_CredentialsTable'
            - 'LiteLLM_ProxyModelTable'
    condition: selection_python and selection_tables
falsepositives:
    - Legitimate LiteLLM proxy administration scripts (should be reviewed)
level: high
```

<!-- audit: validated via sigma convert --without-pipeline -t splunk and -t log_scale; Image|endswith covers python/python3 on both platforms; -c flag + table name AND is specific; legitimate admin queries to these tables are rare and should trigger review -->

### Sigma: Remote Code Loader Lock File Creation

Detects creation of the remote_code_loader.lock mutex file.

compile: pass (sigma convert splunk + logscale) | confidence: high

```yaml
title: LiteLLM Supply Chain - Remote Code Loader Lock File Creation
id: a7e1c5f6-8d2b-4c3e-f0a5-6b9d2e4c7f1a
status: experimental
description: >
    Detects creation of the remote_code_loader.lock file in /tmp, which serves
    as a mutex for the LiteLLM 1.107.0 malicious remote code loading mechanism
    that fetches and executes additional payloads.
references:
    - https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
author: Actioner
date: 2026-10-29
tags:
    - attack.t1105
    - attack.t1059.006
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '/tmp/remote_code_loader.lock'
            - '\Temp\remote_code_loader.lock'
    condition: selection
falsepositives:
    - None known; this filename is specific to the LiteLLM 1.107.0 malware
level: critical
```

<!-- audit: validated via sigma convert --without-pipeline -t splunk and -t log_scale; filename is unique to this malware; file_event category covers Sysmon EID 11 and equivalent -->

### Suricata: HTTP POST Exfiltration to /healthcheck

Detects the encrypted credential exfiltration HTTP POST to the attacker's /healthcheck endpoint.

compile: pass (suricata -T) | confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain Exfiltration POST to /healthcheck"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/healthcheck"; endswith; http.content_type; content:"application/octet-stream"; http.header; content:"X-SHA256"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created_at 2026-10-29; sid:2100101; rev:1;)
```

<!-- audit: validated suricata -T exit 0; dot-notation sticky buffers; http.content_type + http.header X-SHA256 + POST /healthcheck is a highly specific 4-factor AND; may FP on legitimate health endpoints that POST octet-stream with X-SHA256 (very unlikely combination) -->

### Suricata: DNS Query for litellm.dev

Detects DNS resolution of the attacker-controlled exfiltration domain.

compile: pass (suricata -T) | confidence: high

```
alert dns $HOME_NET any -> any any (msg:"Actioner - LiteLLM Supply Chain DNS Query for litellm.dev"; dns.query; content:"litellm.dev"; nocase; endswith; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created_at 2026-10-29; sid:2100102; rev:1;)
```

<!-- audit: validated suricata -T exit 0; dns.query with endswith matches litellm.dev and any subdomain (www.litellm.dev); domain is attacker-controlled not the legitimate litellm.ai; nocase for resilience -->
<!-- caveat: IOC shelf life — litellm.dev may be sinkholed, re-registered, or taken down over time; periodically verify domain ownership before treating alerts as active C2 -->

### YARA: LiteLLM cook.py Credential Stealer

Detects the malicious cook.py payload by characteristic strings.

compile: pass (yarac exit 0) | confidence: high

```yara
rule SupplyChain_LiteLLM_CookPy_Credential_Stealer
{
    meta:
        description = "Detects the malicious cook.py credential stealer from the LiteLLM 1.107.0 supply chain compromise"
        author = "Actioner"
        date = "2026-10-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        severity = "critical"

    strings:
        $s1 = "PRIVCOLLECT_ACTIVE" ascii
        $s2 = "remote_code_loader.lock" ascii
        $s3 = ".pc_once_72129118c59f5636c0bb" ascii
        $s4 = ".pc_e_" ascii
        $s5 = "/healthcheck" ascii
        $s6 = "X-SHA256" ascii
        $s7 = "LiteLLM_CredentialsTable" ascii
        $s8 = "LiteLLM_ProxyModelTable" ascii
        $s9 = "data.bin" ascii
        $s10 = "key.bin" ascii
        $s11 = "hdr.json" ascii

    condition:
        filesize < 1MB and 5 of them
}
```

<!-- revision: changed filesize < 500KB to < 1MB; report states payload is ~500KB which is right at the 500KB boundary -->
<!-- audit: yarac compiled exit 0; 5-of-11 threshold balances detection vs FP; strings are highly specific to this payload; filesize < 1MB scopes to Python scripts not large binaries; data.bin/key.bin/hdr.json alone are generic but combined with PRIVCOLLECT/cook-specific strings are precise -->

### YARA: PRIVCOLLECT Staging Patterns

Detects PRIVCOLLECT credential harvesting strings and staging directory patterns.

compile: pass (yarac exit 0) | confidence: medium

```yara
rule SupplyChain_LiteLLM_PRIVCOLLECT_Strings
{
    meta:
        description = "Detects PRIVCOLLECT credential harvesting strings and staging patterns from the LiteLLM 1.107.0 supply chain compromise"
        author = "Actioner"
        date = "2026-10-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        severity = "critical"

    strings:
        $priv1 = "PRIVCOLLECT_ACTIVE" ascii
        $priv2 = ".pc_once_72129118c59f5636c0bb" ascii
        $priv3 = ".pc_e_" ascii
        $priv4 = ".pc_" ascii
        $staging1 = "/tmp/.pc_once_" ascii
        $staging2 = "/tmp/.pc_e_" ascii
        $exfil1 = "application/octet-stream" ascii
        $exfil2 = "X-SHA256" ascii
        $code_loader = "remote_code_loader" ascii

    condition:
        filesize < 1MB and
        (
            ($priv1 and 2 of ($priv*)) or
            (2 of ($staging*) and 1 of ($exfil*)) or
            ($code_loader and 2 of ($priv*))
        )
}
```

<!-- audit: yarac compiled exit 0; condition uses OR branches for variant coverage; $priv4 ".pc_" is broader and only fires in combination; application/octet-stream and X-SHA256 individually are common but in combination with staging paths are specific; medium confidence due to broader .pc_ pattern -->

### YARA: Embedded RSA Public Key with PRIVCOLLECT Context

Detects files containing RSA public keys alongside PRIVCOLLECT-related credential wrapping context.

<!-- revision: removed ($aes and $oaep) standalone branch — it fired on crypto tutorials and any hybrid encryption tool; now requires at least one $priv* string; downgraded confidence to low -->

compile: pass (yarac exit 0) | confidence: low

```yara
rule SupplyChain_LiteLLM_RSA_PublicKey_Fragment
{
    meta:
        description = "Detects embedded RSA public key fragments used for credential wrapping in the LiteLLM 1.107.0 supply chain compromise"
        author = "Actioner"
        date = "2026-10-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        severity = "medium"

    strings:
        $rsa_begin = "-----BEGIN PUBLIC KEY-----" ascii
        $rsa_end = "-----END PUBLIC KEY-----" ascii
        $priv1 = "PRIVCOLLECT_ACTIVE" ascii
        $priv2 = "remote_code_loader" ascii
        $priv3 = ".pc_e_" ascii

    condition:
        filesize < 1MB and
        $rsa_begin and $rsa_end and
        1 of ($priv*)
}
```

<!-- audit: yarac compiled exit 0; RSA key + PRIVCOLLECT marker is specific; removed $aes/$oaep strings and their standalone branch that would FP on legitimate crypto code; low confidence as an RSA pubkey with one $priv* string is still a broad net -->

### Snort: HTTP POST Exfiltration to /healthcheck

Detects the credential exfiltration HTTP POST pattern.

compile: uncompiled (Snort not installed) | confidence: high

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - LiteLLM Supply Chain Exfiltration POST to /healthcheck"; flow:established,to_server; http_method; content:"POST"; http_uri; content:"/healthcheck"; http_header; content:"application/octet-stream"; content:"X-SHA256"; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created 2026-10-29; sid:2100201; rev:1;)
```

<!-- revision: removed space in flow:established,to_server -->
<!-- audit: structural check only; Snort 3 underscore sticky buffers (http_method, http_uri, http_header); http service in header; flow established,to_server; all options semicolon-terminated; sid/rev present -->

### Snort: DNS Query for litellm.dev

Detects DNS resolution of the attacker-controlled domain via label-length encoding.

compile: uncompiled (Snort not installed) | confidence: high

```
alert udp $HOME_NET any -> any 53 (msg:"Actioner - LiteLLM Supply Chain DNS Query for litellm.dev"; flow:to_server; content:"|07|litellm|03|dev|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/; metadata:author Actioner, created 2026-10-29; sid:2100202; rev:1;)
```

<!-- audit: structural check only; Snort 3 has no DNS sticky buffer so matches label-length-encoded domain in UDP payload; |07| = 7-byte label "litellm", |03| = 3-byte label "dev", |00| = root; udp port 53; nocase for resilience; does not cover TCP DNS or DoH -->

## Lessons Learned

1. **Python startup hooks are a potent supply chain vector.** The `.pth` file mechanism runs code at interpreter startup with no user interaction, making it an ideal persistence/execution technique for supply chain attacks targeting Python environments. The Python ecosystem should consider hardening or opt-in controls for `.pth` execution in production contexts.

2. **Credential brokers are high-value targets.** LiteLLM's role as a proxy that stores API keys for dozens of LLM providers means a single compromise yields access to an organization's entire AI credential surface. Organizations should apply the same security scrutiny to AI infrastructure tooling as they do to identity providers and secret managers.

3. **Hash pinning for Python packages remains underused.** The `--require-hashes` flag for pip would have prevented installation of a tampered wheel, but it is rarely used outside of the most security-conscious environments.

4. **Domain lookalikes for open-source projects persist.** The attacker registered `litellm[.]dev` to impersonate the legitimate project (which uses `litellm.ai`). Domain monitoring and trademark-based takedowns remain essential for popular open-source projects.

5. **This is the third LiteLLM security event in five months.** Following the CVE-2026-42271 RCE (June 2026) and the August 2026 Trivy/supply chain incidents, this October compromise underscores the need for continuous monitoring of the LiteLLM dependency, not just point-in-time vulnerability scanning.

## Sources

- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/) -- primary technical analysis of the LiteLLM 1.107.0 supply chain compromise
- [The Hacker News](https://thehackernews.com/2026/10/leaked-litellm-master-key-let-attackers.html) -- reporting on the leaked master key as the initial access vector
- [The Register](https://www.theregister.com/security/2026/10/26/litellm-supply-chain-attack-started-with-an-exposed-master-key/5305544) -- additional context on the attack timeline and exposed master key

---
*Report generated by Actioner*
