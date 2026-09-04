# Technical Analysis Report: Coder Registry Infrastructure Compromise (2026-09-04)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-04
Version: 2.0 (FINAL)

## Executive Summary

On August 31, 2026, an unidentified threat actor compromised Coder's Cloudflare infrastructure and injected unauthorized IP addresses into the server pool serving `registry.coder.com`. For approximately 14 hours (07:35 -- 21:45 UTC), a subset of Terraform module downloads were routed to attacker-controlled servers that delivered trojanized versions containing credential-stealing scripts. The malicious modules used a `data "external" "telemetry"` block to execute shell scripts (`dlp-docker.sh`, `dlp.sh`) that harvested provisioner secrets, OIDC tokens, SSH keys, cloud API keys, CI/CD credentials, and Coder database passwords, exfiltrating them to the lookalike domain `coder-infra[.]com`. Coder is used by major enterprises and government agencies including Dropbox, Palantir, Mercedes-Benz, and the U.S. government. CVSS 4.0 score is 9.0 (Critical); no CVE has been assigned. The advisory identifier is GHSA-vx42-ghc9-gw65.

## Background: Coder and its Module Registry

[Coder](https://coder.com) is an open-source platform for provisioning and managing remote development environments (Cloud Development Environments / CDEs). Developers use Coder workspace templates that pull Terraform modules from `registry.coder.com` to configure infrastructure. The registry runs behind Cloudflare, which load-balances traffic across a pool of origin servers. Modules are cached locally after first download, meaning only users who fetched modules during the attack window received malicious versions. Coder is deployed by organizations including Dropbox, Palantir, Square, Mercedes-Benz, KKR, EnBW, U.S. government agencies, and defense contractors.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-08-28 | Attacker registers the lookalike domain `coder-infra[.]com` (original IP: `199.91.220[.]205`) |
| 2026-08-31 07:35 | Unauthorized IP addresses appear in the Cloudflare origin pool for `registry.coder.com`; malicious module serving begins |
| 2026-08-31 07:35 -- 21:45 | ~14-hour exposure window; a subset of module requests are routed to attacker-controlled servers delivering trojanized Terraform modules |
| 2026-08-31 21:45 | Unauthorized addresses removed from the origin pool; malicious serving stops |
| 2026-09-01 | Coder publishes GitHub Security Advisory [GHSA-vx42-ghc9-gw65](https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65) |
| 2026-09-01 | Patched versions released: 2.37.0, 2.36.4, 2.35.7, 2.34.9 |
| 2026-09-03 | `coder-infra[.]com` observed resolving to Cloudflare IP addresses (domain moved behind CF) |

## Root Cause: Cloudflare Infrastructure Access

The attacker gained access to Coder's Cloudflare infrastructure configuration and added unauthorized IP addresses to the origin server pool used for the module registry. This caused Cloudflare's load balancer to route a portion of incoming registry requests to attacker-controlled servers instead of legitimate Coder origin servers. The precise method of infrastructure access (credential compromise, API key theft, social engineering, etc.) has not been publicly disclosed.

## Technical Analysis of the Malicious Payload

### 1. Supply Chain Injection via Cloudflare Origin Pool Poisoning

The attacker did not compromise Coder's source code or build pipeline. Instead, they injected malicious servers at the CDN/load-balancer layer by adding unauthorized IPs to the Cloudflare origin pool. This is a network-level supply chain attack: the code on the legitimate registry was unmodified, but some download requests were transparently redirected to attacker servers that served modified module archives.

### 2. Malicious Terraform Module Structure

The trojanized modules included a `data "external" "telemetry"` block -- a Terraform construct that executes an external program and captures its output. This block invoked a shell script (`${path.module}/dlp-docker.sh`) packaged within the module. The `dlp-docker.sh` script in turn called variant-specific `dlp.sh` scripts tailored to different module types (aider, rstudio-server, windows-rdp, zed, and a common variant).

Known compromised script hashes (SHA-256):

| Script | Module Variant | SHA-256 |
|--------|---------------|---------|
| `dlp-docker.sh` | All | `7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398` |
| `dlp.sh` | common | `a7f4fa5f7e33b2a6f6488cf28444584caa449144d246b083de919162f5514247` |
| `dlp.sh` | aider | `414d01f6072fbf05bef513e277f4c2b504a413c8e2aa5bae133a5cbc0cda9dc1` |
| `dlp.sh` | rstudio-server | `a64ce3038f2a501c9735abf6a1f9f04cbddbad53371cd68bec0f7510365c8ffa` |
| `dlp.sh` | windows-rdp | `ebbe0d2ed8cfaf9e19edb38ce44d6b407f9771b5c0813a7add27c05f66e89596` |
| `dlp.sh` | zed | `7ef6b8c3c976fb60b3fa22e9e294ba548d9b532e060c1323a0124a3a7a647f13` |

### 3. C2 Infrastructure

The exfiltration endpoint was `hxxp://www[.]coder-infra[.]com/cli/check`. The domain `coder-infra[.]com` was registered on August 28, 2026 -- three days before the attack began -- and initially resolved to `199.91.220[.]205`. By September 3, the domain had been moved behind Cloudflare IP addresses. HTTP requests to the exfiltration endpoint used the custom header `X-CLI-Token: your-secret-token` for authentication to the attacker's collection infrastructure.

### 4. Credential Harvesting Scope

The malicious scripts targeted different credential categories depending on the execution context:

**When the provisioner ran within `coderd` (template operations):**
- Provisioner environment variables and secrets
- Cloud infrastructure API keys (AWS, GCP, Azure)
- AI tooling credentials
- CI/CD credentials
- Configuration-file secrets and terminal history

**When running during workspace builds (user context):**
- User OIDC tokens
- SSH keys (user-configured)
- External authentication provider tokens (one-time tokens)
- Coder database passwords and configuration secrets

### 5. Anti-Forensics / Evasion Techniques

The attack was designed for stealth: the `data "external" "telemetry"` block was named to appear as legitimate telemetry collection. The exfiltration domain `coder-infra.com` mimicked Coder's legitimate infrastructure naming. By operating at the CDN layer, the attacker avoided modifying any code in the actual Coder repository, leaving no git commit trail. The malicious modules were only served intermittently (when Cloudflare happened to route to the attacker's origin), making the attack non-deterministic and harder to detect.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Coder Terraform modules (various) | Modules downloaded from `registry.coder.com` between 07:35--21:45 UTC on 2026-08-31 | Trojanized modules containing `data "external" "telemetry"` block and `dlp-docker.sh`/`dlp.sh` credential stealers |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `${module_path}/dlp-docker.sh` | 7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398 | Primary credential harvesting script (entrypoint) |
| Linux | `${module_path}/dlp.sh` (common) | a7f4fa5f7e33b2a6f6488cf28444584caa449144d246b083de919162f5514247 | Common variant credential harvester |
| Linux | `${module_path}/dlp.sh` (aider) | 414d01f6072fbf05bef513e277f4c2b504a413c8e2aa5bae133a5cbc0cda9dc1 | Aider module-specific credential harvester |
| Linux | `${module_path}/dlp.sh` (rstudio-server) | a64ce3038f2a501c9735abf6a1f9f04cbddbad53371cd68bec0f7510365c8ffa | RStudio Server module-specific credential harvester |
| Linux | `${module_path}/dlp.sh` (windows-rdp) | ebbe0d2ed8cfaf9e19edb38ce44d6b407f9771b5c0813a7add27c05f66e89596 | Windows RDP module-specific credential harvester |
| Linux | `${module_path}/dlp.sh` (zed) | 7ef6b8c3c976fb60b3fa22e9e294ba548d9b532e060c1323a0124a3a7a647f13 | Zed module-specific credential harvester |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `coder-infra[.]com` | Exfiltration destination (lookalike domain, registered 2026-08-28) |
| Domain | `www[.]coder-infra[.]com` | Exfiltration endpoint host |
| IP | `199.91.220[.]205` | Original IP of `coder-infra[.]com` exfiltration server |
| URL Pattern | `hxxp://www[.]coder-infra[.]com/cli/check` | Exfiltration endpoint |
| HTTP Header | `X-CLI-Token: your-secret-token` | Custom authentication header to attacker C2 |

### Behavioral

- Terraform `data "external" "telemetry"` block executing shell scripts from the module directory during `terraform apply`
- Shell script execution chain: `terraform` -> `dlp-docker.sh` -> `dlp.sh` harvesting environment variables, SSH keys, OIDC tokens, and configuration files
- HTTP POST to `coder-infra[.]com/cli/check` with exfiltrated credential data
- Provisioner log entries containing `data.external.telemetry` references

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attacker injected malicious servers into Coder's Cloudflare origin pool to serve trojanized Terraform modules |
| T1584.004 | Compromise Infrastructure: Server | Attacker gained access to Coder's Cloudflare configuration and added unauthorized origin servers to the module registry pool |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Malicious `dlp-docker.sh` and `dlp.sh` bash scripts executed via Terraform `data "external"` block |
| T1005 | Data from Local System | Scripts harvested environment variables, SSH keys, configuration files, terminal history |
| T1552.001 | Unsecured Credentials: Credentials In Files | Targeted configuration-file secrets, database passwords, API keys stored in environment |
| T1041 | Exfiltration Over C2 Channel | Stolen credentials exfiltrated to `coder-infra[.]com/cli/check` via HTTP |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP used for exfiltration with custom `X-CLI-Token` header |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Lookalike domain `coder-infra.com` mimicking legitimate Coder infrastructure; telemetry block named to blend with legitimate telemetry |

## Impact Assessment

**Breadth:** Any organization using Coder that downloaded or refreshed Terraform modules from `registry.coder.com` during the 14-hour window on August 31 is potentially affected. Coder is used by high-profile organizations including Dropbox, Palantir, Square, Mercedes-Benz, KKR, EnBW, U.S. government agencies, and defense contractors.

**Depth:** Critical -- the malicious modules had access to provisioner secrets, cloud API keys, database passwords, OIDC tokens, and SSH keys. Successful exfiltration could enable follow-on attacks including cloud infrastructure takeover, lateral movement, and data breaches.

**Stealth:** High -- the attack operated at the CDN layer with no code repository modifications, used a convincing lookalike domain, and named the malicious Terraform block "telemetry" to blend in. Non-deterministic delivery (only a subset of requests routed to malicious servers) made detection harder.

## Detection & Remediation

### Immediate Detection

**Search provisioner logs for the malicious Terraform block:**
```
grep -r "data.external.telemetry" /path/to/provisioner/logs/
```

**Check firewall/proxy/DNS logs for the exfiltration domain:**
```
# DNS logs
grep -i "coder-infra.com" /var/log/dns*

# Proxy logs
grep -i "coder-infra.com" /var/log/proxy*

# VPC flow logs -- search for connections to 199.91.220.205
```

**SQL query to identify affected template versions (from Coder advisory):**
Run the pre-built SQL queries provided in the [GHSA-vx42-ghc9-gw65 advisory](https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65) against your Coder deployment database to identify impacted template versions, affected workspaces, and cached modules.

### Remediation

1. **Identify exposure:** Run the Coder-provided SQL queries to determine which template versions and workspaces used modules downloaded during the August 31 attack window (07:35--21:45 UTC)
2. **Purge malicious cached packages:** Use the SQL DELETE transaction provided in the advisory to clear potentially compromised cached modules
3. **Rotate ALL potentially exposed credentials:** This includes cloud API keys, CI/CD tokens, OIDC tokens, SSH keys, database passwords, and any secrets accessible to the provisioner environment
4. **Update Coder:** Upgrade to patched versions: 2.37.0, 2.36.4, 2.35.7, or 2.34.9 (depending on your release track). Note: versions 2.37.0, 2.36.4, 2.35.7, and 2.34.9 must be applied before any further upgrade
5. **Review infrastructure:** Audit cloud infrastructure for unauthorized access using the potentially compromised credentials
6. **Monitor for follow-on activity:** Watch for unusual cloud API calls, new IAM roles/users, or unauthorized resource provisioning

### Long-Term Hardening

- **Module integrity verification:** Implement hash verification for downloaded Terraform modules; pin module versions and verify checksums in CI/CD pipelines
- **Network segmentation:** Restrict provisioner outbound network access to only required endpoints; block arbitrary HTTP egress from provisioner environments
- **Cloudflare/CDN security:** Enable change alerting and audit logging for origin pool modifications; enforce multi-factor authentication on CDN management accounts; implement infrastructure-as-code for CDN configuration with change approval workflows
- **Secret management:** Use dedicated secret managers (Vault, AWS Secrets Manager) rather than environment variables; implement short-lived, scoped credentials for provisioning

## Detection Rules

These detections target the Coder registry supply chain compromise IOCs: the exfiltration domain `coder-infra[.]com`, the attacker IP `199.91.220[.]205`, the malicious `data.external.telemetry` Terraform block, and the `dlp-docker.sh`/`dlp.sh` credential-harvesting scripts. All rules are PoC/advisory-specific (default altitude, strict leniency). Sigma rules convert cleanly to Splunk and CrowdStrike LogScale; `sigma check` could not validate due to a proxy-blocked MITRE ATT&CK data fetch (network issue, not a rule defect). YARA rules compile clean with yarac 4.5.0. Suricata rules validate clean with Suricata 7.0.3.

### Sigma: DNS Query to Coder Exfiltration Domain

Detects DNS resolution of `coder-infra.com`, the attacker-registered lookalike domain used for credential exfiltration.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data fetch 403, network/proxy issue — not a rule defect); splunk convert exit 0: QueryName="*coder-infra.com"; log_scale convert exit 0: QueryName=/coder-infra\.com$/i. Known malicious domain, zero benign-use expectation. -->
```yaml
title: DNS Query to Coder Registry Exfiltration Domain
id: 8a3c1f7e-b2d4-4e6a-9f81-3c5d7e9a0b42
status: experimental
description: >
    Detects DNS queries to the attacker-controlled lookalike domain coder-infra.com
    used as the exfiltration endpoint in the Coder registry supply chain compromise
    of August 31, 2026.
references:
    - https://www.bleepingcomputer.com/news/security/coders-registry-infrastructure-compromised-to-push-malicious-modules/
    - https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65
author: Actioner
date: 2026/09/04
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'coder-infra.com'
    condition: selection
falsepositives:
    - Unlikely - this is a known malicious domain registered for this campaign
level: critical
```

### Sigma: Network Connection to Coder Exfiltration IP

Detects outbound connections to `199.91.220.205`, the original IP of the attacker exfiltration server.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data fetch 403, network/proxy issue); splunk convert exit 0: DestinationIp="199.91.220.205"; log_scale convert exit 0. Known attacker IP; may be reassigned over time — scope to incident window for long-term use. -->
```yaml
title: Network Connection to Coder Registry Exfiltration IP
id: 2f9b4d6e-a1c3-47e5-8d09-6b2e8f1a3c5d
status: experimental
description: >
    Detects outbound network connections to IP address 199.91.220.205, the original
    IP hosting the coder-infra.com exfiltration endpoint used in the Coder registry
    supply chain compromise.
references:
    - https://www.bleepingcomputer.com/news/security/coders-registry-infrastructure-compromised-to-push-malicious-modules/
    - https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65
author: Actioner
date: 2026/09/04
tags:
    - attack.t1041
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '199.91.220.205'
    condition: selection
falsepositives:
    - Unlikely - this is a known attacker-controlled IP address
level: critical
```

### Sigma: Malicious Terraform External Data Block in Provisioner Logs

Detects the `data.external.telemetry` pattern and `dlp-docker.sh`/`dlp.sh` script names characteristic of the compromised Coder modules.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data fetch 403, network/proxy issue); splunk convert exit 0; log_scale convert exit 0. Distinctive strings from advisory — dlp-docker.sh and data.external.telemetry are highly specific. Condition requires terraform process AND specific indicator strings, or specific indicators alone. -->
<!-- revision: fixed condition logic — selection_terraform no longer fires independently on every `terraform apply`; must co-occur with telemetry/script indicators. Fixed tag attack.t1059 → attack.t1059.004 (Unix Shell sub-technique). -->
```yaml
title: Malicious Terraform External Data Block in Coder Provisioner Logs
id: 4e7a9c2d-f5b1-48d3-a6e0-8d3f2c1b7e5a
status: experimental
description: >
    Detects the malicious data.external.telemetry block pattern in provisioner or
    Terraform execution logs, characteristic of the compromised Coder registry
    modules that harvested credentials via dlp-docker.sh/dlp.sh scripts.
references:
    - https://www.bleepingcomputer.com/news/security/coders-registry-infrastructure-compromised-to-push-malicious-modules/
    - https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65
author: Actioner
date: 2026/09/04
tags:
    - attack.t1059.004
    - attack.t1005
logsource:
    category: process_creation
    product: linux
detection:
    selection_terraform:
        Image|endswith:
            - '/terraform'
        CommandLine|contains: 'apply'
    selection_telemetry:
        CommandLine|contains:
            - 'data.external.telemetry'
    selection_scripts:
        CommandLine|contains:
            - 'dlp-docker.sh'
            - 'dlp.sh'
    condition: (selection_terraform and (selection_telemetry or selection_scripts)) or selection_telemetry or selection_scripts
falsepositives:
    - Legitimate use of external data blocks named telemetry (uncommon)
level: high
```

### Sigma: HTTP Connection to Coder Exfiltration Endpoint

Detects web proxy traffic to the exfiltration domain `coder-infra[.]com` and its known `/cli/check` path.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check failed (MITRE data fetch 403, network/proxy issue); splunk convert exit 0; log_scale convert exit 0. Known malicious domain + exfiltration URI path. -->
<!-- revision: fixed Boolean absorption (condition was `A or (A and B)` = just `A`); narrowed to `A and B`. Fixed field cs-uri-stem → c-uri-stem (standard Sigma proxy field). Changed cs-host|contains → cs-host|endswith for domain IOC precision. -->
```yaml
title: HTTP Connection to Coder Exfiltration Endpoint
id: 6c8d3e2f-a4b5-49e1-9c07-5a1d8f3e2b6c
status: experimental
description: >
    Detects HTTP connections to the known exfiltration endpoint
    coder-infra.com/cli/check used by the malicious Terraform modules
    in the Coder registry supply chain compromise.
references:
    - https://www.bleepingcomputer.com/news/security/coders-registry-infrastructure-compromised-to-push-malicious-modules/
    - https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65
author: Actioner
date: 2026/09/04
tags:
    - attack.t1041
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_domain:
        cs-host|endswith: 'coder-infra.com'
    selection_uri:
        c-uri-stem|contains: '/cli/check'
    condition: selection_domain and selection_uri
falsepositives:
    - Unlikely - known malicious domain and exfiltration path
level: critical
```

### Suricata: DNS Query to Coder Exfiltration Domain

Detects DNS queries for `coder-infra.com` at the network level using Suricata's `dns.query` buffer.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 validate exit 0. dot-notation buffer (dns.query), correct protocol (dns), semicolons terminate all options, sid in 2200000+ range, msg prefixed "Actioner - ", metadata present. Known malicious domain. -->
<!-- revision: updated compile status — suricata 7.0.3 is installed; rule validates clean. -->
```suricata
alert dns $HOME_NET any -> any any (
    msg:"Actioner - DNS Query to Coder Exfil Domain coder-infra.com";
    flow:to_server;
    dns.query;
    content:"coder-infra.com"; nocase; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.bleepingcomputer.com/news/security/coders-registry-infrastructure-compromised-to-push-malicious-modules/;
    reference:url,github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65;
    metadata:author Actioner, created_at 2026-09-04;
    sid:2200001;
    rev:1;
)
```

### Suricata: HTTP Request to Coder Exfiltration Endpoint

Detects HTTP connections to `coder-infra.com/cli/check` with Suricata dot-notation sticky buffers.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata 7.0.3 validate exit 0. dot-notation buffers (http.host, http.uri), correct protocol (http), semicolons present, sid:2200002. Real (non-defanged) values in rule. Known malicious endpoint. -->
<!-- revision: updated compile status — suricata 7.0.3 is installed; rule validates clean. -->
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Actioner - HTTP Request to Coder Exfil Endpoint coder-infra.com/cli/check";
    flow:established,to_server;
    http.host;
    content:"coder-infra.com"; fast_pattern;
    http.uri;
    content:"/cli/check"; startswith;
    classtype:trojan-activity;
    reference:url,www.bleepingcomputer.com/news/security/coders-registry-infrastructure-compromised-to-push-malicious-modules/;
    reference:url,github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65;
    metadata:author Actioner, created_at 2026-09-04;
    sid:2200002;
    rev:1;
)
```

### Snort: N/A

Suricata rules cover the network detection layer for this topic. While Snort 3 supports `dns_query` (underscore syntax), the DNS and HTTP rules use Suricata-specific features (`startswith` modifier, dot-notation buffers) that would need rewriting for Snort syntax. For this single-domain IOC set, the Suricata rules provide equivalent coverage without a separate Snort port.
<!-- revision: corrected claim that Snort 3 "lacks dns.query" — Snort 3 has `dns_query` (underscore). Reworded to accurately explain why Snort rules were omitted. -->

### YARA: Coder Registry Malicious DLP Scripts

Detects the credential-stealing `dlp-docker.sh`/`dlp.sh` scripts by matching the exfiltration domain, custom HTTP header, and script-name strings characteristic of the compromised Coder modules.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac 4.5.0 compile exit 0. Valid string definitions with modifiers (ascii, wide), condition uses filesize constraint and logical combinations, meta section complete with all required fields. Strings are drawn directly from the advisory (exfil domain, header name, script names). -->
<!-- revision: updated compile status — yarac 4.5.0 is installed; both rules compile clean. Renamed second rule from hash-based to string-based (hashes are metadata only, detection is string-based). -->
```yara
rule Coder_Registry_Malicious_DLP_Script
{
    meta:
        description = "Detects malicious dlp-docker.sh or dlp.sh credential-stealing scripts from the Coder registry supply chain compromise"
        author = "Actioner"
        date = "2026-09-04"
        reference = "https://www.bleepingcomputer.com/news/security/coders-registry-infrastructure-compromised-to-push-malicious-modules/"
        severity = "critical"

    strings:
        $exfil_domain = "coder-infra.com" ascii wide
        $exfil_path = "/cli/check" ascii wide
        $header = "X-CLI-Token" ascii wide
        $tf_block = "data.external" ascii
        $script1 = "dlp-docker.sh" ascii
        $script2 = "dlp.sh" ascii
        $telemetry = "telemetry" ascii

    condition:
        filesize < 1MB and
        ($exfil_domain or ($exfil_path and $header)) and
        (1 of ($script*) or ($tf_block and $telemetry))
}

rule Coder_Registry_Malicious_Module_Strings
{
    meta:
        description = "Detects compromised Terraform modules from the Coder registry attack using malicious string patterns"
        author = "Actioner"
        date = "2026-09-04"
        reference = "https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65"
        hash1 = "7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398"
        hash2 = "a7f4fa5f7e33b2a6f6488cf28444584caa449144d246b083de919162f5514247"
        hash3 = "414d01f6072fbf05bef513e277f4c2b504a413c8e2aa5bae133a5cbc0cda9dc1"
        hash4 = "a64ce3038f2a501c9735abf6a1f9f04cbddbad53371cd68bec0f7510365c8ffa"
        hash5 = "ebbe0d2ed8cfaf9e19edb38ce44d6b407f9771b5c0813a7add27c05f66e89596"
        hash6 = "7ef6b8c3c976fb60b3fa22e9e294ba548d9b532e060c1323a0124a3a7a647f13"
        severity = "critical"

    strings:
        $exfil = "coder-infra.com" ascii
        $script_name1 = "dlp-docker.sh" ascii
        $script_name2 = "dlp.sh" ascii

    condition:
        filesize < 500KB and
        $exfil and 1 of ($script_name*)
}
```

## Lessons Learned

1. **CDN/infrastructure layer is a supply chain attack surface.** Organizations securing their code repositories and build pipelines may overlook the CDN configuration layer. Origin pool poisoning bypasses code-signing and repository integrity checks because the content is replaced at the delivery layer, not the source.

2. **Terraform's `data "external"` block is a powerful execution primitive.** Any Terraform module with an external data source can execute arbitrary code during `terraform plan` or `terraform apply`. Organizations should audit modules for external data sources and restrict which modules are permitted in templates.

3. **Credential scoping matters.** The broad impact of this attack stems from provisioners having access to a wide range of secrets (cloud keys, database passwords, OIDC tokens). Applying least-privilege to provisioner credentials and using short-lived, scoped tokens would limit the blast radius of similar compromises.

4. **Module caching is a double-edged sword.** Terraform's module cache meant that only users who fetched modules during the attack window were affected (limiting blast radius), but it also means compromised modules persist locally even after the registry is cleaned -- requiring explicit purging.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [BleepingComputer: Coder's registry infrastructure compromised to push malicious modules](https://www.bleepingcomputer.com/news/security/coders-registry-infrastructure-compromised-to-push-malicious-modules/) -- primary news coverage with IOCs, timeline, and exfiltration details
- [GitHub Security Advisory GHSA-vx42-ghc9-gw65](https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65) -- official Coder security advisory with file hashes, SQL detection queries, and remediation guidance
- [PRSOL:CC: Coder's registry infrastructure compromised](https://www.prsol.cc/2026/09/04/coders-registry-infrastructure-compromised-to-push-malicious-modules/) -- additional coverage with detection and credential-scope details
- [Blogspan: Coder-Registry gekapert](https://www.blogspan.net/coder-registry-ip-pool-schadcode/) -- German-language coverage with timeline and domain registration details
- [OffSeq Threat Radar](https://radar.offseq.com/threat/coders-registry-infrastructure-compromised-to-push-malicious-modules-81210132fe11d0b2) -- threat intelligence feed entry with severity classification

---
*Report generated by Actioner*
