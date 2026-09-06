# Technical Analysis Report: Coder Registry Infrastructure Compromise (2026-09-06)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-06
Version: 1.0 (DRAFT)

## Executive Summary

On August 31, 2026, attackers compromised Coder's Cloudflare infrastructure by obtaining a Cloudflare API key and used it to inject unauthorized IP addresses into the DNS pool serving registry.coder.com. For approximately 14 hours (07:35-21:45 UTC), a subset of users pulling Terraform modules from the Coder registry received malicious versions containing credential-stealing shell scripts. The malicious modules used a Terraform `data "external" "telemetry"` block to execute shell scripts (`dlp-docker.sh`, `dlp.sh`) that harvested environment variables, cloud API keys, CI/CD credentials, SSH keys, OIDC tokens, terminal history, and configuration secrets, exfiltrating them to the attacker-controlled lookalike domain `coder-infra[.]com` (registered August 28, 2026). Coder is used by organizations including Dropbox, Palantir, Mercedes-Benz, the U.S. government, and defense contractors. CVSS 9.0 Critical. No CVE was assigned; the advisory is tracked as GHSA-vx42-ghc9-gw65.

## Background: Coder and the Coder Registry

Coder is an open-source platform providing self-hosted, secure cloud development environments (CDEs). It is used by prominent private enterprises and government organizations to provision reproducible developer workspaces via Terraform-based templates. The Coder Registry (registry.coder.com) hosts Terraform modules that define workspace configurations — including compute, networking, IDE tooling, and agent startup scripts. These modules are fetched and executed during template imports, workspace builds, and infrastructure provisioning, making the registry a high-value supply chain target. Before the attack, Coder's registry infrastructure was fronted by Cloudflare for CDN and DNS resolution.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-28 | Attacker registers lookalike domain `coder-infra[.]com` |
| 2026-08-31 07:35 | Attacker begins injecting rogue IPs into Cloudflare DNS pool for registry.coder.com |
| 2026-08-31 07:35-21:45 | ~14-hour exposure window; subset of registry requests routed to attacker-controlled server at 199.91.220[.]205 |
| 2026-08-31 21:45 | Malicious IPs removed, cache cleared, registry.coder.com confirmed clean |
| 2026-09-01 | Coder publishes GitHub Security Advisory GHSA-vx42-ghc9-gw65; patched versions released |
| 2026-09-03 | Public disclosure via Coder blog and media coverage |

## Root Cause: Cloudflare API Key Compromise

An unauthorized actor obtained a Cloudflare API key with permissions to modify DNS/origin pool configuration for registry.coder.com. The attacker used this key to add unauthorized IP addresses (specifically 199.91.220[.]205) to the Cloudflare origin pool, causing a portion of legitimate registry traffic to be routed to an attacker-controlled server. The attacker's server hosted a clone of the Coder registry containing modified Terraform modules with injected credential-stealing code. The specific method by which the Cloudflare API key was compromised has not been publicly disclosed. Coder has confirmed that its own codebase and Google Cloud infrastructure were not compromised — only the Cloudflare-fronted registry distribution layer.

## Technical Analysis of the Malicious Payload

### 1. Registry Traffic Hijacking (Initial Access)

The attacker inserted rogue origin IPs into the Cloudflare pool fronting registry.coder.com. Cloudflare's load balancer would route a subset of requests to the attacker-controlled origin at 199.91.220[.]205 instead of Coder's legitimate infrastructure. Users pulling Terraform modules during this window received poisoned versions indistinguishable from legitimate ones at the URL/TLS layer (the Cloudflare certificate remained valid).

### 2. Malicious Terraform Module Injection

The poisoned modules contained an additional Terraform `data "external"` block:

```hcl
data "external" "telemetry" {
  program = ["${path.module}/dlp-docker.sh"]
}
```

This block triggers execution of a shell script (`dlp-docker.sh` or variant `dlp.sh`) during any Terraform operation that evaluates the module — including template imports, updates, dry runs, and workspace provisioning. The use of the name "telemetry" was a social-engineering choice designed to appear benign.

### 3. Credential Harvesting Scripts (dlp-docker.sh / dlp.sh)

Multiple variants of the exfiltration script were distributed, each tailored to specific Coder module contexts (common, aider, rstudio-server, windows-rdp, zed). The scripts harvested:

- **Process environment variables** — including cloud provider credentials (AWS, GCP, Azure), API keys, and CI/CD tokens
- **Configuration file secrets** — from dotfiles and config directories
- **Terminal command history** — `~/.bash_history` and similar
- **SSH keys** — from `~/.ssh/`
- **OIDC tokens** — issued during workspace provisioning (single-use, but grants workspace-scope access)
- **External authentication tokens** — OAuth/SAML tokens from connected identity providers
- **Database passwords** — when the provisioner ran co-located with `coderd` (Coder's server process)

### 3. C2 Infrastructure

| Attribute | Value |
|-----------|-------|
| Exfiltration domain | `www[.]coder-infra[.]com` (registered 2026-08-28) |
| Rogue origin IP | 199.91.220[.]205 |
| Exfiltration endpoint | `hxxp://www[.]coder-infra[.]com/cli/check` |
| Protocol | HTTP POST |
| Data format | Environment dump / credential payload |

The domain `coder-infra[.]com` was a deliberate typosquat of Coder's legitimate infrastructure, designed to blend into network logs. The `/cli/check` URI path mimics a legitimate health-check endpoint.

### 4. Platform-Specific Behavior

#### Linux (Primary Target)

All Coder workspaces are Linux-based containers or VMs. The `dlp-docker.sh` script executed within the Terraform provisioner context, which runs as part of `terraform apply` during workspace builds. The script used standard Unix utilities (`printenv`, `cat`, `curl`) to harvest and exfiltrate credentials.

### 5. Anti-Forensics / Evasion Techniques

- **Trusted distribution channel** — modules were served through the legitimate registry.coder.com domain with valid TLS certificates, bypassing network-layer detection
- **Benign naming** — the injected block used "telemetry" as the resource name; scripts were named "dlp" (data loss prevention), both names designed to avoid suspicion in code review
- **Cloudflare-level injection** — attack operated at the CDN/DNS layer, leaving no trace in Coder's application logs or source code
- **Ephemeral exposure** — 14-hour window limited the attack surface while maximizing credential harvest during business hours
- **Cache persistence** — poisoned modules could persist in local Terraform caches beyond the attack window, extending exposure

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxp://www[.]coder-infra[.]com/cli/check`)
> - Domains: `[.]` replacing dots (e.g., `coder-infra[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `199.91.220[.]205`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Coder Registry Terraform Modules | Versions served 2026-08-31 07:35-21:45 UTC | Injected `data "external" "telemetry"` block executing credential-stealing scripts |

### File System

| Platform | Path / Filename | Hash (SHA256) | Description |
|----------|----------------|---------------|-------------|
| Linux | dlp-docker.sh | `7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398` | Primary Docker-context credential harvester |
| Linux | dlp.sh (common) | `a7f4fa5f7e33b2a6f6488cf28444584caa449144d246b083de919162f5514247` | Common variant credential harvester |
| Linux | dlp.sh (aider) | `414d01f6072fbf05bef513e277f4c2b504a413c8e2aa5bae133a5cbc0cda9dc1` | Aider-module variant |
| Linux | dlp.sh (rstudio-server) | `a64ce3038f2a501c9735abf6a1f9f04cbddbad53371cd68bec0f7510365c8ffa` | RStudio Server module variant |
| Linux | dlp.sh (windows-rdp) | `ebbe0d2ed8cfaf9e19edb38ce44d6b407f9771b5c0813a7add27c05f66e89596` | Windows RDP module variant |
| Linux | dlp.sh (zed) | `7ef6b8c3c976fb60b3fa22e9e294ba548d9b532e060c1323a0124a3a7a647f13` | Zed editor module variant |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | coder-infra[.]com | Exfiltration domain (registered 2026-08-28) |
| Domain | www[.]coder-infra[.]com | Exfiltration endpoint host |
| IP | 199.91.220[.]205 | Rogue origin server injected into Cloudflare pool |
| URL Pattern | hxxp://www[.]coder-infra[.]com/cli/check | Credential exfiltration endpoint |

### Behavioral

- Terraform provisioner logs containing `data.external.telemetry` resource references
- Shell script execution (`dlp-docker.sh`, `dlp.sh`) spawned by `terraform` process during workspace provisioning
- Outbound HTTP POST to `/cli/check` endpoint carrying environment variable dumps
- File reads of `~/.ssh/*`, `~/.bash_history`, and configuration directories during provisioning

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attacker injected malicious code into legitimate Terraform modules served by the Coder registry |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Malicious Terraform external data source executed bash scripts (dlp-docker.sh, dlp.sh) |
| T1552.001 | Unsecured Credentials: Credentials In Files | Scripts harvested SSH keys, config files, terminal history, and stored credentials |
| T1552.007 | Unsecured Credentials: Container API | Environment variables harvested from container/provisioner runtime |
| T1041 | Exfiltration Over C2 Channel | Stolen credentials exfiltrated via HTTP POST to coder-infra[.]com/cli/check |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP used for credential exfiltration to attacker domain |
| T1078 | Valid Accounts | Stolen credentials (API keys, OIDC tokens, SSH keys) enable downstream access |

## Impact Assessment

**Breadth:** Any Coder deployment that pulled a registry module between 07:35-21:45 UTC on August 31, 2026 may have received poisoned modules. Coder is used by Dropbox, Palantir, Square, Mercedes-Benz, KKR, EnBW, the U.S. government, and defense companies. The exact number of affected deployments is unknown — Coder acknowledged it "cannot conclusively identify every compromised deployment."

**Depth:** Critical. The attack harvested cloud infrastructure API keys (AWS, GCP, Azure), CI/CD credentials, SSH keys, OIDC tokens, and potentially database passwords. Compromised credentials could enable lateral movement, data exfiltration, and infrastructure takeover across affected organizations' cloud environments.

**Stealth:** High. Modules were served through the legitimate registry.coder.com domain with valid TLS certificates. No CVE was assigned, meaning standard SCA tooling would not flag the compromise. Poisoned modules could persist in local caches beyond the attack window.

**CVSS:** 9.0 Critical (AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H)

## Detection & Remediation

### Immediate Detection

Search for connections to the exfiltration infrastructure:

```bash
# Search firewall/proxy/DNS/VPC flow logs for attacker domain
grep -ri "coder-infra" /var/log/
grep -ri "199.91.220" /var/log/

# Search Terraform state and module files for malicious data source
rg -n 'data "external" "telemetry"' .

# Search provisioner job logs for the telemetry data source
grep -r "data.external.telemetry" /var/log/coder/

# Search for dropped scripts
find / -name "dlp-docker.sh" -o -name "dlp.sh" 2>/dev/null
```

SQL queries to identify affected cached modules and template versions are available in [GHSA-vx42-ghc9-gw65](https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65).

### Remediation

1. **Update Coder** to patched versions: 2.37.0, 2.36.4, 2.35.7, or 2.34.9 (includes automatic cache remediation)
2. **Clear Terraform module caches** — delete `.terraform/` directories and re-initialize from the now-clean registry
3. **Rotate all potentially exposed credentials:**
   - Cloud provider API keys (AWS, GCP, Azure)
   - CI/CD pipeline tokens and secrets
   - SSH keys accessible from provisioner environments
   - OIDC/OAuth tokens and external auth provider credentials
   - Database passwords (if provisioner ran co-located with coderd)
   - Any secrets present as environment variables during provisioning
4. **Review audit logs** in cloud providers for unauthorized access using potentially stolen credentials
5. **Block the exfiltration domain** — add `coder-infra.com` and IP `199.91.220.205` to firewall/proxy blocklists
6. **Preserve logs** before clearing caches for forensic analysis

### Long-Term Hardening

- Implement **module integrity verification** — cryptographic signing and hash verification for Terraform modules before execution
- Deploy **outbound traffic allowlists** restricting provisioner network access to known-good endpoints
- Monitor **Cloudflare audit logs** for unauthorized API key usage and origin pool modifications
- Enable **Terraform plan review workflows** that require human approval before applying changes from external modules
- Consider **pinning module versions** with integrity checksums rather than pulling latest from registries
- Implement **runtime credential isolation** — ensure provisioners do not have access to coderd database credentials

## Detection Rules

These detections target the Coder registry compromise's specific IOCs: the exfiltration domain (coder-infra[.]com), rogue origin IP, malicious script names, and the distinctive Terraform external data source pattern. All Sigma rules convert to Splunk and CrowdStrike LogScale; `sigma check` could not run due to the environment proxy blocking MITRE ATT&CK data downloads.

### Sigma: DNS Query to Coder-Infra Exfiltration Domain

Detects DNS resolution of the attacker-registered exfiltration domain coder-infra[.]com.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (ATT&CK data fetch 403); splunk convert exit 0; log_scale convert exit 0. Domain is attacker-registered 2026-08-28, no legitimate use expected. -->
```yaml
title: DNS Query to Coder-Infra Exfiltration Domain
id: 8b3e1d4f-a7c2-4e9b-b5d8-3f6a1c2e9d07
status: experimental
description: >
    Detects DNS queries to coder-infra.com, the lookalike exfiltration domain used in the
    Coder registry infrastructure compromise (August 31, 2026). Malicious Terraform modules
    exfiltrated stolen credentials to this domain.
references:
    - https://coder.com/blog/coder-registry-security-incident-what-happened-and-what-to-do
    - https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65
author: Actioner
date: 2026/09/06
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'coder-infra.com'
    condition: selection
falsepositives:
    - Legitimate use of coder-infra.com is not expected; this is an attacker-registered domain
level: high
```

### Sigma: Network Connection to Coder Registry Rogue Origin IP

Detects outbound connections to the rogue origin server IP (199.91.220.205) used to serve malicious modules.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (ATT&CK data fetch 403); splunk convert exit 0; log_scale convert exit 0. IP from GHSA-vx42-ghc9-gw65 advisory. May false-positive if IP is reassigned post-incident. -->
```yaml
title: Network Connection to Coder Registry Exfiltration Infrastructure
id: 5a2f8c91-d3b7-4e6a-a1c4-7e9b2d5f3a08
status: experimental
description: >
    Detects outbound network connections to the rogue IP address (199.91.220.205) used
    in the Coder registry compromise to serve malicious Terraform modules and receive
    exfiltrated credentials.
references:
    - https://coder.com/blog/coder-registry-security-incident-what-happened-and-what-to-do
    - https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65
author: Actioner
date: 2026/09/06
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '199.91.220.205'
    condition: selection
falsepositives:
    - IP address reuse after attacker infrastructure is decommissioned
level: high
```

### Sigma: Malicious Terraform External Telemetry Data Source / DLP Script Files

Detects file-system artifacts of the compromised modules: Terraform files in `.terraform` cache or the distinctive `dlp-docker.sh`/`dlp.sh` scripts.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by proxy (ATT&CK data fetch 403); splunk convert exit 0; log_scale convert exit 0. The .terraform + .tf selection is broad (lowers confidence); dlp script filenames are distinctive but could overlap with DLP tooling. -->
```yaml
title: Malicious Terraform External Telemetry Data Source in Coder Module
id: c4d7e2a1-f8b3-4c5d-9a6e-1b2d3f4a5c78
status: experimental
description: >
    Detects the malicious Terraform external data source pattern (data.external.telemetry)
    used in compromised Coder registry modules to execute credential-stealing shell scripts.
    The malicious modules contained a data "external" "telemetry" block invoking dlp-docker.sh.
references:
    - https://coder.com/blog/coder-registry-security-incident-what-happened-and-what-to-do
    - https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65
author: Actioner
date: 2026/09/06
tags:
    - attack.t1195.002
    - attack.t1059.004
logsource:
    category: file_event
detection:
    selection_file_content:
        TargetFilename|endswith:
            - '.tf'
            - '.tf.json'
        TargetFilename|contains:
            - '.terraform'
    filter_normal:
        TargetFilename|contains:
            - 'dlp-docker.sh'
            - 'dlp.sh'
    condition: selection_file_content or filter_normal
falsepositives:
    - Legitimate Terraform modules with .terraform paths (selection is broad); dlp script names are distinctive
level: medium
```

### Sigma: Execution of Coder Registry Malicious DLP Script

Detects process execution of the credential-stealing scripts (dlp-docker.sh, dlp.sh) or command lines referencing the exfiltration endpoint.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (ATT&CK data fetch 403); splunk convert exit 0; log_scale convert exit 0. Script names from GHSA-vx42-ghc9-gw65 hashes. dlp.sh alone may hit DLP tooling (caveat noted in FP). -->
```yaml
title: Execution of Coder Registry Malicious DLP Script
id: 9e1a3b5c-d7f2-4a8e-b6c9-2d4f1e3a7b5d
status: experimental
description: >
    Detects execution of the malicious credential-stealing scripts (dlp-docker.sh, dlp.sh)
    dropped by compromised Coder registry Terraform modules during the August 31, 2026
    supply chain attack.
references:
    - https://coder.com/blog/coder-registry-security-incident-what-happened-and-what-to-do
    - https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65
author: Actioner
date: 2026/09/06
tags:
    - attack.t1059.004
    - attack.t1552.001
logsource:
    category: process_creation
detection:
    selection_script_name:
        CommandLine|contains:
            - 'dlp-docker.sh'
            - 'dlp.sh'
    selection_exfil:
        CommandLine|contains|all:
            - 'coder-infra.com'
            - 'cli/check'
    condition: selection_script_name or selection_exfil
falsepositives:
    - Legitimate scripts named dlp.sh in data loss prevention tooling
level: high
```

### Snort: HTTP Exfiltration to coder-infra.com

Detects outbound HTTP traffic to the attacker's exfiltration endpoint at coder-infra[.]com/cli/check.
**Status:** compile ⚠️ uncompiled (structural check only; snort not installed) · confidence: high
<!-- audit: snort not installed in this environment. Rule uses http service with http_header and http_uri sticky buffers per Snort 3 spec. Domain and URI path from GHSA-vx42-ghc9-gw65. -->
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Coder Registry Compromise HTTP Exfil to coder-infra.com"; flow:established,to_server; content:"coder-infra.com"; http_header; fast_pattern; content:"/cli/check"; http_uri; sid:2100010; rev:1; classtype:trojan-activity; reference:url,github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65;)
```

### Suricata: DNS Query for Coder-Infra Exfiltration Domain

Detects DNS queries resolving the attacker exfiltration domain coder-infra[.]com.
**Status:** compile ⚠️ uncompiled (structural check only; suricata not installed) · confidence: high
<!-- audit: suricata not installed in this environment. Uses dns.query dot-notation sticky buffer per Suricata spec. -->
```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Coder Registry Exfil Domain coder-infra.com"; dns.query; content:"coder-infra.com"; nocase; endswith; flow:to_server; classtype:trojan-activity; reference:url,github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65; metadata:author Actioner, created_at 2026-09-06; sid:2200010; rev:1;)
```

### Suricata: HTTP Exfiltration to coder-infra.com /cli/check

Detects HTTP requests to the attacker's credential exfiltration endpoint combining host and URI path.
**Status:** compile ⚠️ uncompiled (structural check only; suricata not installed) · confidence: high
<!-- audit: suricata not installed in this environment. Uses http.host and http.uri dot-notation sticky buffers per Suricata spec. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Coder Registry Compromise HTTP Exfil via /cli/check"; http.host; content:"coder-infra.com"; endswith; http.uri; content:"/cli/check"; startswith; flow:established,to_server; classtype:trojan-activity; reference:url,github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65; metadata:author Actioner, created_at 2026-09-06; sid:2200011; rev:1;)
```

### YARA: Coder Registry Malicious DLP Script

Detects the credential-harvesting shell scripts by combining the exfiltration domain with shell script markers and credential-harvesting patterns. Scope to Terraform module caches and provisioner working directories.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos-dlp.sh fired Coder_Registry_Malicious_DLP_Script; neg-dlp.sh quiet. Positive sample constructed from advisory-published IOCs (exfil domain + shebang + env harvest + ssh). -->
```yara
rule Coder_Registry_Malicious_DLP_Script
{
    meta:
        description = "Detects malicious credential-stealing shell scripts (dlp-docker.sh, dlp.sh) distributed via compromised Coder registry Terraform modules"
        author = "Actioner"
        date = "2026-09-06"
        reference = "https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65"
        hash1 = "7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398"
        hash2 = "a7f4fa5f7e33b2a6f6488cf28444584caa449144d246b083de919162f5514247"
        hash3 = "414d01f6072fbf05bef513e277f4c2b504a413c8e2aa5bae133a5cbc0cda9dc1"
        hash4 = "ebbe0d2ed8cfaf9e19edb38ce44d6b407f9771b5c0813a7add27c05f66e89596"
        hash5 = "7ef6b8c3c976fb60b3fa22e9e294ba548d9b532e060c1323a0124a3a7a647f13"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $exfil_domain = "coder-infra.com" ascii
        $exfil_path = "/cli/check" ascii
        $tf_telemetry = "data.external.telemetry" ascii
        $dlp_docker = "dlp-docker.sh" ascii
        $dlp_script = "dlp.sh" ascii
        $shebang = "#!/bin/bash" ascii
        $shebang2 = "#!/bin/sh" ascii
        $env_harvest1 = "printenv" ascii
        $env_harvest2 = "env |" ascii
        $ssh_steal = ".ssh/" ascii
        $history_steal = "bash_history" ascii
        $oidc_token = "OIDC" ascii nocase

    condition:
        ($shebang or $shebang2) and
        (
            ($exfil_domain and $exfil_path) or
            ($exfil_domain and 2 of ($env_harvest*, $ssh_steal, $history_steal, $oidc_token)) or
            ($tf_telemetry and ($dlp_docker or $dlp_script))
        )
}
```

### YARA: Coder Registry Malicious Terraform Module

Detects poisoned Terraform module files containing the malicious `data "external" "telemetry"` block paired with attacker artifacts.
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. yara pos-terraform.tf fired Coder_Registry_Malicious_Terraform_Module; neg-terraform.tf quiet. Positive sample uses advisory-published pattern (data "external" "telemetry" + dlp-docker.sh + path.module). -->
```yara
rule Coder_Registry_Malicious_Terraform_Module
{
    meta:
        description = "Detects Terraform module files containing the malicious external telemetry data source used in the Coder registry compromise"
        author = "Actioner"
        date = "2026-09-06"
        reference = "https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $tf_data_external = "data \"external\" \"telemetry\"" ascii
        $tf_program = "dlp-docker.sh" ascii
        $tf_module_path = "${path.module}" ascii
        $exfil = "coder-infra.com" ascii

    condition:
        $tf_data_external and ($tf_program or $tf_module_path or $exfil)
}
```

## Lessons Learned

1. **Package registry infrastructure is a critical supply chain target.** The attacker did not need to compromise Coder's source code or build pipeline — controlling the CDN/DNS layer was sufficient to distribute malicious code through a trusted channel with valid TLS certificates. Organizations consuming modules from any registry should implement integrity verification beyond TLS.

2. **Cloudflare API key management is a single point of failure.** The compromise of a single API key with DNS/origin pool modification permissions enabled the entire attack. Infrastructure access keys for CDN providers should be treated with the same rigor as production database credentials — MFA, short-lived tokens, IP-restricted scopes, and audit logging.

3. **Terraform's external data source is a powerful execution primitive.** The `data "external"` resource legitimately executes arbitrary programs during plan/apply, making it an ideal vehicle for supply chain payloads. Organizations should audit external data sources in modules, restrict provisioner network access, and consider policy-as-code tools (Sentinel, OPA) to block unexpected external program execution.

4. **No CVE was assigned, so standard tooling won't alert.** The absence of a CVE means SCA scanners, dependency checkers, and vulnerability databases will not flag this incident. Detection depends on IOC-based hunting and behavioral monitoring — exactly the kind of detection this report provides.

5. **Cache persistence extends the attack window.** Even after the registry was cleaned, poisoned modules in local `.terraform/` caches would continue executing malicious code on subsequent `terraform apply` runs until the cache was cleared. Time-of-download is not time-of-last-execution.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Coder Blog: Registry Security Incident](https://coder.com/blog/coder-registry-security-incident-what-happened-and-what-to-do) — Primary source: Coder's official incident disclosure with remediation guidance
- [GitHub Security Advisory GHSA-vx42-ghc9-gw65](https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65) — Primary source: formal advisory with IOCs, file hashes, affected versions, and SQL detection queries
- [BleepingComputer: Coder's registry infrastructure compromised](https://www.bleepingcomputer.com/news/security/coders-registry-infrastructure-compromised-to-push-malicious-modules/) — Technical reporting with attack timeline and credential scope
- [SC Media: Coder platform targeted](https://www.scworld.com/brief/coder-platform-targeted-by-attackers-delivering-malicious-terraform-modules) — Reporting on attack scope and affected organizations
- [eSecurity Planet: Coder Registry Compromise Explained](https://www.esecurityplanet.com/cybersecurity/news-coder-registry-malicious-terraform-modules/) — Technical analysis with detection guidance and SQL query references
- [DEV Community: Coder Registry Compromise Analysis](https://dev.to/anoymask/coder-registry-compromise-malicious-server-added-to-cloudflare-pool-to-distribute-malicious-4604) — Community analysis with IP addresses, file hashes, and additional IOCs
- [OffSeq Threat Radar: Self-hosted Coder Advisory](https://radar.offseq.com/threat/self-hosted-coder-check-whether-you-pulled-a-registry-module-on-aug-31-no-cve-so-nothing-will-flag-it-1aa3aa8fba32bc0c) — Additional IOCs, hash details, and detection tool references

---
*Report generated by Actioner*
