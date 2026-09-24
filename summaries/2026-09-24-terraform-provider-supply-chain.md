# Graphalgo Malware: Malicious Terraform Providers & Go Modules Supply-Chain Attack

> **DRAFT** -- generated 2026-09-24 | Analyst: Actioner (automated)

---

## Executive Summary

Cybersecurity researchers at [Aikido Security](https://www.aikido.dev/blog/graphalgo-terraform-go-modules) have disclosed the first confirmed case of malware distribution through HashiCorp's centralized Terraform registry. The campaign distributes Go-based malware through two trojanized Terraform providers and two malicious Go modules, extending the previously documented **Graphalgo** campaign attributed to DPRK-linked threat actors (Lazarus Group). The malware employs a dual command-and-control architecture using Slack workspaces and Ethereum smart contracts on the Arbitrum Sepolia testnet, and is capable of executing arbitrary Go or JavaScript code on compromised developer machines. At least 18 unique victims across Windows, Linux, and macOS have been observed in the threat actor's C2 channels. The attack places infrastructure-as-code (IaC) workflows squarely in the supply-chain attack surface, as `terraform init` automatically downloads and executes provider code with the deploying engineer's full access privileges.

---

## Background

The Graphalgo campaign was first documented by [ReversingLabs in February 2026](https://www.reversinglabs.com/blog/npm-fake-install-logs-rat), initially targeting developers through malicious npm and PyPI packages distributed via fake Web3 job recruitment schemes. By April 2026, the campaign had expanded with a shared cryptographic public key linking npm payloads to Go-based malware. In September 2026, Aikido Security identified the campaign's expansion into Terraform providers and Go modules, marking the first known abuse of HashiCorp's Terraform registry as a malware delivery vector.

The legitimate `kreuzwerker/docker` Terraform provider (56 million downloads) was typosquatted as `kreuzwenker/docker`, exploiting visual similarity to lure developers. The attack leverages `terraform init` behavior, which automatically downloads and executes provider binaries, giving a malicious provider the same system access as the deploying engineer.

---

## Attack Timeline

| Date | Event |
|------|-------|
| May 2025 | Graphalgo campaign origin (npm/PyPI packages targeting crypto developers) |
| February 2026 | ReversingLabs publicly documents Graphalgo campaign with 192 malicious packages |
| April 2026 | Graphalgo resurgence; shared public key links npm payloads to Go malware |
| Jul 16, 2026 | Earliest observed Slack C2 check-in (test account hostname "Frank", username "Frank1") |
| Aug 6, 2026 | Earliest blockchain C2 transaction on Arbitrum Sepolia |
| Aug 11, 2026 | Go module `gocommunity.io/orderedbtree` published |
| Sep 8, 2026 | Go module `gogets.dev/btreex` published (with forged commit dates backdated to Nov 2025) |
| Sep 22, 2026 | Aikido Security publishes disclosure |
| Sep 23, 2026 | The Hacker News reports on the campaign |

---

## Root Cause Analysis

The attack exploits the trust model of the Terraform provider registry, which allows any GitHub user to publish providers without code review or security vetting. When `terraform init` is executed, Terraform downloads and runs provider binaries locally with the full privileges of the deploying user. There is no sandboxing, signature verification from a trusted authority, or behavioral analysis of provider code. Combined with typosquatting of a high-profile provider name, this creates a viable supply-chain entry point.

---

## Technical Analysis

### Delivery Mechanism

The malware is delivered through four packages:

**Terraform Providers (via registry.terraform.io):**
- `gocommunity-io/dockerd` -- purpose-built malicious provider
- `kreuzwenker/docker` -- typosquat of legitimate `kreuzwerker/docker` (note: 'n' vs 'r')

**Go Modules (via Go module proxy/pkg.go.dev):**
- `gocommunity.io/orderedbtree` -- contained plaintext malware
- `gogets.dev/btreex` -- malware disguised as SQL archive

### Activation Mechanism

The Terraform providers employ a targeted activation gate: two Terraform input variables (`containerName` and `networkID`) are concatenated and SHA-256 hashed. The resulting hash must match a hardcoded trigger value (`b9966e3...`). This hash is then used as the AES decryption key for the payload archive, ensuring the malware only activates for the intended victim and preventing sandbox analysis.

### Execution Chain

1. `terraform init` downloads the malicious provider
2. Provider code in `internal/provider/resource_docker_container_funcs.go` checks activation condition
3. On match, decrypts a disguised archive (`examples/resources/docker_container/import-resource.sqlite3`)
4. Unpacks and decrypts the archive contents
5. Executes the payload as a detached `go run .` process (second-stage Go code)

### Command and Control

The malware implements dual C2 channels with distinct roles:

**Slack C2 (10-second polling interval):**
- Check-in workspace: `portfolio-devs.slack[.]com`, channel `frontend-devs`
- Command workspace: `portfolio-testers.slack[.]com`, channel `qa-announcements`
- Historical workspace: `mediumstar.slack[.]com`

**Blockchain C2 (3-second polling interval):**
- Network: Arbitrum Sepolia testnet
- Smart contract: `0xAD02b5cDE693529d3bdA0266299501ad0193036C`
- Methods: `setCPubKey`, `serviceData1`, `serviceData2`
- Write-only access via `setCPubKey` prevents rogue clients from disrupting C2

### Encryption and Key Exchange

- Ephemeral ECDH key exchange per client
- Shared key derived from ephemeral keys + threat actor public key
- Per-victim encryption prevents cross-host message leakage
- Hardcoded public key: `302a300506032b656e032100bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702`

### Reconnaissance

On initial check-in, the malware collects and reports:
- Operating system and architecture
- Hostname and username
- Home directory path
- Node.js availability (via `exec.LookPath("node")`)
- Timestamp

### Capabilities

- Execute arbitrary Go code
- Execute JavaScript via Node.js
- Self-deletion / indicator removal

### Observed Victim Telemetry

- 18 unique hostnames across 725 check-in messages
- Platform distribution: 3 Windows, 5 Linux, 10 macOS
- 1,240 encrypted Slack messages since Jul 16, 2026
- 1,402 blockchain transactions since Aug 6, 2026

### Anti-Forensics

- Forged Git commit dates in `gogets-dev/btreex` repository backdated to November 2025; Go module proxy treats commit dates authoritatively, displaying falsified release dates on pkg.go.dev
- Periodic removal of malware from GitHub to extend account longevity
- Obfuscated function naming (e.g., `_ddb43801486d()`)

---

## Indicators of Compromise (IOCs)

> All indicators are defanged for safe handling. Detection rules use real (non-defanged) values.

### Malicious Packages

| Type | Package | Notes |
|------|---------|-------|
| Terraform Provider | `gocommunity-io/dockerd` | Attacker-controlled |
| Terraform Provider | `kreuzwenker/docker` | Typosquat of `kreuzwerker/docker` |
| Go Module | `gocommunity[.]io/orderedbtree` | Published Aug 11, 2026 |
| Go Module | `gogets[.]dev/btreex` | Published Sep 8, 2026 |

### File Hashes (SHA-256)

| Artifact | Hash |
|----------|------|
| Encrypted ZIP archive (both Terraform providers) | `5f892a5424e88a21a3eb3d7f82ebf04d8ac31cdb19ada25153be4165df977d0f` |
| Encrypted archive (btreex module) | `ab01686d87565250fc4989faddb877d793667b07ec217a61cbd798f5695d62f5` |
| Activation trigger hash | `b9966e3762e9a0d5d263b8cb3cca07294f81af9714d40ddf4628cb85d74e8ad5` |

### Network Infrastructure

| Type | Indicator | Purpose |
|------|-----------|---------|
| Domain | `gocommunity[.]io` | Fake Go ecosystem vanity domain |
| Domain | `gogets[.]dev` | Fake Go ecosystem vanity domain |
| Slack Workspace | `portfolio-devs[.]slack[.]com` | C2 check-in channel |
| Slack Workspace | `portfolio-testers[.]slack[.]com` | C2 command channel |
| Slack Workspace | `mediumstar[.]slack[.]com` | Historical C2 |
| Ethereum Contract | `0xAD02b5cDE693529d3bdA0266299501ad0193036C` | Arbitrum Sepolia C2 |

### Cryptographic Indicators

| Type | Value |
|------|-------|
| Threat Actor Public Key | `302a300506032b656e032100bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702` |

### File Paths

| Path | Context |
|------|---------|
| `internal/provider/resource_docker_container_funcs.go` | Malicious entry point in trojanized provider |
| `examples/resources/docker_container/import-resource.sqlite3` | Disguised encrypted payload archive |

### GitHub Accounts (Threat Actor Controlled)

`gocommunity-io`, `gogets-dev`, `go-pack-tech`, `kreuzwenker`, `victormmpp`, `markcary3`, `steveb082`, `go-community-admin`

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Context |
|-------------|----------------|---------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Malicious Go modules introduced as dependencies |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized Terraform providers in HashiCorp registry |
| T1059 | Command and Scripting Interpreter | Execution of arbitrary Go/JavaScript on victims |
| T1071.001 | Application Layer Protocol: Web Protocols | Slack API and Ethereum RPC used for C2 |
| T1102.002 | Web Service: Bidirectional Communication | Slack workspaces and blockchain smart contract as C2 |
| T1105 | Ingress Tool Transfer | Second-stage payload decrypted and executed |
| T1140 | Deobfuscate/Decode Files or Information | AES decryption of payload archive |
| T1041 | Exfiltration Over C2 Channel | System reconnaissance data exfiltrated via Slack/blockchain |
| T1070 | Indicator Removal | Self-deletion capability; periodic GitHub cleanup |
| T1583.001 | Acquire Infrastructure: Domains | `gocommunity[.]io` and `gogets[.]dev` registered for campaign |
| T1036 | Masquerading | Typosquatting of `kreuzwerker/docker`; forged commit dates |
| T1008 | Fallback Channels | Dual C2 via Slack and blockchain |

---

## Impact Assessment

**Severity: HIGH**

- **Scope**: Any developer or CI/CD pipeline that ran `terraform init` with a configuration referencing the malicious providers is potentially compromised
- **Access**: The malware executes with the full privileges of the deploying user, which in IaC workflows typically includes cloud provider credentials, SSH keys, and API tokens
- **Attribution**: DPRK/Lazarus Group -- financially motivated, targeting cryptocurrency and Web3 developers
- **Novel vector**: First confirmed use of Terraform providers as a malware distribution channel, establishing a new supply-chain attack surface for the IaC ecosystem
- **Observed victims**: 18 unique hosts (3 Windows, 5 Linux, 10 macOS)

---

## Detection & Remediation

### Detection Recommendations

1. **Audit Terraform lock files** (`.terraform.lock.hcl`) for references to `kreuzwenker/docker` or `gocommunity-io/dockerd`
2. **Search Go module caches** (`$GOPATH/pkg/mod/`) for `gocommunity.io/orderedbtree` or `gogets.dev/btreex`
3. **Monitor DNS** for queries to `gocommunity[.]io` and `gogets[.]dev`
4. **Monitor Slack API traffic** for connections to the identified C2 workspaces
5. **Monitor Ethereum RPC traffic** for interactions with contract `0xAD02b5cDE693529d3bdA0266299501ad0193036C`
6. **Inspect process trees** for `terraform` spawning `go run` child processes
7. **Search for file artifacts**: `import-resource.sqlite3` in Terraform provider directories
8. **Scan binaries/source** with the YARA rules below for the hardcoded public key and C2 indicators

### Remediation Steps

1. Remove any Terraform state referencing the malicious providers and re-init with legitimate providers
2. Rotate all credentials accessible from affected machines (cloud provider tokens, SSH keys, API keys)
3. Audit CI/CD pipelines for unexpected `terraform init` activity
4. Review `.terraform/providers/` directories for the malicious provider binaries
5. Block the identified domains and Slack workspaces at the network perimeter
6. Consider Terraform provider pinning and hash verification in `.terraform.lock.hcl`

---

## Detection Rules

### Sigma Rules

#### 1. DNS Query to Graphalgo Campaign Domains

Detects DNS resolution of the attacker-registered vanity domains used to host malicious Go modules and support the fake ecosystem.

<!-- audit: Validated with sigma check (0 errors, 0 issues), sigma convert --without-pipeline -t splunk (pass), sigma convert --without-pipeline -t log_scale (pass). sigma check ATT&CK tag validator excluded due to proxy-blocked MITRE data fetch (HTTP 403); tags verified manually against ATT&CK v15. -->

**Compile status**: `sigma check` pass (0 errors) | `sigma convert -t splunk` pass | `sigma convert -t log_scale` pass
**Confidence**: HIGH -- attacker-registered domains with no legitimate use

```yaml
title: DNS Query to Graphalgo Terraform Campaign C2 Domains
id: 7a4e1b3c-9d2f-4e8a-b5c1-6f0d3e2a7b94
status: experimental
description: >
    Detects DNS queries to domains associated with the Graphalgo malicious
    Terraform provider and Go module supply-chain campaign, including fake
    ecosystem vanity domains used for malware distribution.
references:
    - https://www.aikido.dev/blog/graphalgo-terraform-go-modules
    - https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html
author: Actioner
date: 2026-09-24
tags:
    - attack.t1195.002
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - 'gocommunity.io'
            - 'gogets.dev'
    condition: selection
falsepositives:
    - Unlikely; these are attacker-registered domains with no legitimate use
level: high
```

**Splunk SPL:**
```
QueryName IN ("*gocommunity.io", "*gogets.dev")
```

**CrowdStrike LogScale:**
```
QueryName=/gocommunity\.io$/i or QueryName=/gogets\.dev$/i
```

---

#### 2. DNS Query to Graphalgo Slack C2 Workspaces

Detects DNS queries to the specific Slack workspaces used for encrypted C2 check-ins and command delivery.

<!-- audit: Validated with sigma check (0 errors, 0 issues), sigma convert --without-pipeline -t splunk (pass), sigma convert --without-pipeline -t log_scale (pass). sigma check ATT&CK tag validator excluded due to proxy-blocked MITRE data fetch. -->

**Compile status**: `sigma check` pass (0 errors) | `sigma convert -t splunk` pass | `sigma convert -t log_scale` pass
**Confidence**: MEDIUM -- Slack workspace names could theoretically coincide with legitimate organizations, though the combination is highly specific

```yaml
title: Network Connection to Graphalgo Slack C2 Workspaces
id: 2c8f5d1a-3b7e-4a9c-d6e0-8f1a2b3c4d5e
status: experimental
description: >
    Detects DNS queries to Slack workspaces used as C2 channels in the
    Graphalgo malicious Terraform provider campaign. The threat actor uses
    portfolio-devs, portfolio-testers, and mediumstar Slack workspaces for
    encrypted check-ins and command delivery.
references:
    - https://www.aikido.dev/blog/graphalgo-terraform-go-modules
    - https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html
author: Actioner
date: 2026-09-24
tags:
    - attack.t1071.001
    - attack.t1102.002
logsource:
    category: dns_query
detection:
    selection:
        QueryName|contains:
            - 'portfolio-devs.slack.com'
            - 'portfolio-testers.slack.com'
            - 'mediumstar.slack.com'
    condition: selection
falsepositives:
    - Organizations legitimately using Slack workspaces with these exact names
level: medium
```

**Splunk SPL:**
```
QueryName IN ("*portfolio-devs.slack.com*", "*portfolio-testers.slack.com*", "*mediumstar.slack.com*")
```

**CrowdStrike LogScale:**
```
QueryName=/portfolio-devs\.slack\.com/i or QueryName=/portfolio-testers\.slack\.com/i or QueryName=/mediumstar\.slack\.com/i
```

---

#### 3. Suspicious Go Process Spawned by Terraform Init

Detects the second-stage execution pattern where a terraform process spawns a detached `go run` child process, characteristic of the Graphalgo malware payload activation.

<!-- audit: Validated with sigma check (0 errors, 0 issues), sigma convert --without-pipeline -t splunk (pass), sigma convert --without-pipeline -t log_scale (pass). sigma check ATT&CK tag validator excluded due to proxy-blocked MITRE data fetch. Process creation category requires Sysmon EID 1 or equivalent endpoint telemetry. -->

**Compile status**: `sigma check` pass (0 errors) | `sigma convert -t splunk` pass | `sigma convert -t log_scale` pass
**Confidence**: HIGH -- terraform should not spawn go run processes under normal operation

```yaml
title: Suspicious Detached Go Process Spawned by Terraform Init
id: 9e3a7c5b-1d4f-2e8b-a6c0-3f5d7e9b1a2c
status: experimental
description: >
    Detects terraform init spawning a detached go run process, which is
    characteristic of the Graphalgo malicious Terraform provider executing
    its second-stage payload after decrypting the disguised archive.
references:
    - https://www.aikido.dev/blog/graphalgo-terraform-go-modules
    - https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html
author: Actioner
date: 2026-09-24
tags:
    - attack.t1195.002
    - attack.t1059
logsource:
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '/terraform'
            - '\terraform.exe'
    selection_child:
        Image|endswith:
            - '/go'
            - '\go.exe'
        CommandLine|contains: 'run'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Terraform providers that compile or run Go code during init (rare)
level: high
```

**Splunk SPL:**
```
ParentImage IN ("*/terraform", "*\\terraform.exe") Image IN ("*/go", "*\\go.exe") CommandLine="*run*"
```

**CrowdStrike LogScale:**
```
ParentImage=/\/terraform$/i or ParentImage=/\\terraform\.exe$/i Image=/\/go$/i or Image=/\\go\.exe$/i CommandLine=/run/i
```

---

### YARA Rules

#### 4. Graphalgo Terraform Provider Payload Strings

Detects the Graphalgo malware payload based on characteristic strings including the hardcoded threat actor public key, Slack C2 workspace names, Ethereum smart contract address, and reconnaissance patterns.

<!-- audit: Compiled with yarac (exit code 0). Rule uses campaign-specific strings (public key, contract address, workspace names) that are highly distinctive. The public key alone is a strong singular indicator. -->

**Compile status**: `yarac` pass (exit 0)
**Confidence**: CRITICAL (on $pubkey or $contract match) / HIGH (on combination matches)

```yara
rule Malware_Graphalgo_Terraform_Provider_Strings
{
    meta:
        description = "Detects Graphalgo malware payload distributed via malicious Terraform providers and Go modules, based on characteristic strings including the hardcoded public key, C2 workspace names, smart contract address, and reconnaissance function patterns"
        author = "Actioner"
        date = "2026-09-24"
        reference = "https://www.aikido.dev/blog/graphalgo-terraform-go-modules"
        hash = "5f892a5424e88a21a3eb3d7f82ebf04d8ac31cdb19ada25153be4165df977d0f"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Hardcoded threat actor public key (unique to Graphalgo campaign)
        $pubkey = "bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702" ascii wide nocase

        // C2 Slack workspace names
        $slack1 = "portfolio-devs.slack.com" ascii wide
        $slack2 = "portfolio-testers.slack.com" ascii wide
        $slack3 = "mediumstar.slack.com" ascii wide

        // Slack channel names used for C2
        $chan1 = "frontend-devs" ascii wide
        $chan2 = "qa-announcements" ascii wide

        // Arbitrum Sepolia smart contract address
        $contract = "0xAD02b5cDE693529d3bdA0266299501ad0193036C" ascii wide nocase

        // Smart contract method names
        $method1 = "setCPubKey" ascii wide
        $method2 = "serviceData1" ascii wide
        $method3 = "serviceData2" ascii wide

        // Malware infrastructure domains
        $domain1 = "gocommunity.io" ascii wide
        $domain2 = "gogets.dev" ascii wide

        // Disguised payload file names
        $file1 = "import-resource.sqlite3" ascii wide
        $file2 = "btreex.sql" ascii wide

    condition:
        filesize < 50MB and
        (
            $pubkey or
            $contract or
            (2 of ($slack*)) or
            (1 of ($method*) and 1 of ($slack*)) or
            (1 of ($domain*) and 1 of ($file*)) or
            (1 of ($chan*) and 1 of ($method*))
        )
}
```

---

#### 5. Graphalgo Trojanized Terraform Provider Source

Detects trojanized Terraform provider source code containing the Graphalgo malware activation mechanism, including the trigger hash and obfuscated function names.

<!-- audit: Compiled with yarac (exit code 0). The trigger hash and obfuscated function name are highly specific to this campaign. -->

**Compile status**: `yarac` pass (exit 0)
**Confidence**: HIGH -- trigger hash and obfuscated function name are campaign-specific

```yara
rule Malware_Graphalgo_Terraform_Trojanized_Provider
{
    meta:
        description = "Detects trojanized Terraform provider source code containing the Graphalgo malware activation mechanism in the Docker container resource functions file"
        author = "Actioner"
        date = "2026-09-24"
        reference = "https://www.aikido.dev/blog/graphalgo-terraform-go-modules"
        severity = "high"
        tlp = "WHITE"

    strings:
        // Malicious entry point file path
        $path1 = "internal/provider/resource_docker_container_funcs.go" ascii wide

        // Obfuscated malware function name pattern
        $func1 = "_ddb43801486d" ascii wide

        // Reconnaissance helper
        $recon1 = "helper.Keys()" ascii wide

        // Trigger hash (SHA256 of containerName + networkID)
        $trigger = "b9966e3762e9a0d5d263b8cb3cca07294f81af9714d40ddf4628cb85d74e8ad5" ascii wide nocase

        // Payload archive path within provider
        $archive = "examples/resources/docker_container/import-resource.sqlite3" ascii wide

    condition:
        filesize < 50MB and
        (
            $trigger or
            $func1 or
            ($path1 and $archive) or
            ($recon1 and 1 of ($path1, $archive))
        )
}
```

---

### Suricata Rules

#### 6. DNS Query to Graphalgo C2 Domains

Detects DNS queries to the attacker-registered infrastructure domains used in the Graphalgo Terraform campaign.

<!-- audit: Structural check only -- suricata not installed. Verified: dot-notation buffers (dns.query), semicolons terminate all options, required fields (msg, sid, rev) present, dns protocol matches dns.query buffer. -->

**Compile status**: uncompiled (structural check only)
**Confidence**: HIGH

```
alert dns $HOME_NET any -> any any (
    msg:"Actioner - DNS Query to Graphalgo C2 Domain gocommunity.io";
    flow:to_server;
    dns.query;
    content:"gocommunity.io"; nocase; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.aikido.dev/blog/graphalgo-terraform-go-modules;
    metadata:author Actioner, created_at 2026-09-24;
    sid:2100101;
    rev:1;
)

alert dns $HOME_NET any -> any any (
    msg:"Actioner - DNS Query to Graphalgo C2 Domain gogets.dev";
    flow:to_server;
    dns.query;
    content:"gogets.dev"; nocase; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.aikido.dev/blog/graphalgo-terraform-go-modules;
    metadata:author Actioner, created_at 2026-09-24;
    sid:2100102;
    rev:1;
)
```

---

#### 7. DNS Query to Graphalgo Slack C2 Workspaces

Detects DNS queries to the specific Slack workspace subdomains used for C2 communication.

<!-- audit: Structural check only -- suricata not installed. Verified: dot-notation, semicolons, required fields, dns protocol. -->

**Compile status**: uncompiled (structural check only)
**Confidence**: MEDIUM

```
alert dns $HOME_NET any -> any any (
    msg:"Actioner - DNS Query to Graphalgo Slack C2 Workspace portfolio-devs";
    flow:to_server;
    dns.query;
    content:"portfolio-devs.slack.com"; nocase; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.aikido.dev/blog/graphalgo-terraform-go-modules;
    metadata:author Actioner, created_at 2026-09-24;
    sid:2100103;
    rev:1;
)

alert dns $HOME_NET any -> any any (
    msg:"Actioner - DNS Query to Graphalgo Slack C2 Workspace portfolio-testers";
    flow:to_server;
    dns.query;
    content:"portfolio-testers.slack.com"; nocase; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.aikido.dev/blog/graphalgo-terraform-go-modules;
    metadata:author Actioner, created_at 2026-09-24;
    sid:2100104;
    rev:1;
)

alert dns $HOME_NET any -> any any (
    msg:"Actioner - DNS Query to Graphalgo Slack C2 Workspace mediumstar";
    flow:to_server;
    dns.query;
    content:"mediumstar.slack.com"; nocase; fast_pattern;
    classtype:trojan-activity;
    reference:url,www.aikido.dev/blog/graphalgo-terraform-go-modules;
    metadata:author Actioner, created_at 2026-09-24;
    sid:2100105;
    rev:1;
)
```

---

## Sources

1. [Aikido Security -- "Graphalgo campaign spreads to Terraform providers and Go Modules"](https://www.aikido.dev/blog/graphalgo-terraform-go-modules) -- Primary research source (Sep 22, 2026)
2. [The Hacker News -- "Attackers Use Malicious Terraform Providers to Deliver Go Malware via HashiCorp Registry"](https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html) -- Secondary reporting (Sep 23, 2026)
3. [ReversingLabs -- "Malicious npm packages use fake install logs to load RAT"](https://www.reversinglabs.com/blog/npm-fake-install-logs-rat) -- Original Graphalgo campaign documentation (Feb 2026)
4. [GBHackers -- "Graphalgo Malware Uses Malicious Terraform Providers and Go Modules to Deploy RAT"](https://gbhackers.com/graphalgo-malware/) -- Additional analysis
5. [Cybersecurity News -- "The Malware Hiding in Developer Tools That Turned Terraform Providers Into Attack Paths"](https://cybersecuritynews.com/malware-hiding-in-developer-tools/) -- Additional analysis
6. [Purple Shield Security -- "Graphalgo Terraform Malware Targets Cloud Credentials"](https://www.purpleshieldsecurity.com/post/graphalgo-terraform-provider-malware) -- Additional analysis

---

*Report generated by Actioner | DRAFT -- requires peer review before distribution*
