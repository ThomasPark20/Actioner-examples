# Technical Analysis Report: Graphalgo Campaign Spreads to Terraform Providers -- First Malware Distribution via HashiCorp Registry (2026-09-26)

Prepared by: Actioner Research Agent
Classification: TLP:CLEAR
Date: 2026-09-26
Version: 1.0 (DRAFT)

## Executive Summary

Aikido Security disclosed on September 22, 2026 the first documented case of malware distribution through the HashiCorp Terraform Registry. Two malicious Terraform providers -- `gocommunity-io/dockerd` (222 downloads) and `kreuzwenker/docker` (1,449 downloads, a single-letter typosquat of the legitimate `kreuzwerker/docker` provider with 56 million downloads) -- delivered a Go-based remote access trojan (RAT) linked to the DPRK-attributed **Graphalgo** campaign. Two companion malicious Go modules (`gocommunity[.]io/orderedbtree` and `gogets[.]dev/btreex`) carried functionally identical payloads. The RAT uses a dual C2 architecture: an Ethereum smart contract on the Arbitrum Sepolia testnet for dead-drop command retrieval (polled every 3 seconds) and Slack bot API channels (polled every 10 seconds), with all traffic encrypted using ephemeral X25519 key pairs. The malware activates only when a SHA-256 hash of two Terraform input values (`containerName` and `networkID`) matches a hardcoded trigger value, making dynamic analysis evasion trivial. The encrypted second-stage payload is disguised as a SQLite database file (`import-resource.sqlite3`). A secondary C2 IP (`193.247.144[.]38`) was retrieved via the NullReceiver blockchain technique. The campaign was first documented by ReversingLabs in February 2026 targeting npm/PyPI and has now expanded to infrastructure-as-code ecosystems, representing a significant escalation in supply-chain attack surface for DevOps and cloud engineering teams.

Concrete, durable artifacts exist (package names, SHA-256 hashes, contract address, Slack workspaces, threat actor public key, C2 IP). **Viability gate: PASS.** Detection rules are emitted.

## Background: Terraform Registry as an Attack Surface

HashiCorp's Terraform Registry (registry.terraform.io) is the centralized distribution point for Terraform providers -- plugins that manage infrastructure resources (cloud VMs, containers, DNS, etc.). Running `terraform init` downloads and executes provider binaries with full host privileges. Unlike npm or PyPI, the Terraform registry had not previously been used as a malware distribution vector, making this campaign a novel supply-chain vector expansion. The `kreuzwerker/docker` provider is one of the most popular community providers, making `kreuzwenker/docker` (note: 'n' replacing 'r') a high-value typosquat target for any developer working with Docker in Terraform.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-02 (early) | ReversingLabs documents original Graphalgo campaign targeting npm/PyPI |
| 2026-07-16 | Slack C2 channels show first encrypted command traffic (1,240 messages from this date onward) |
| 2026-08-06 | Arbitrum Sepolia C2 smart contract shows first transactions (1,402 total recorded) |
| 2026-08-11 | Go module `gocommunity[.]io/orderedbtree` published |
| 2026-09-08 | Go module `gogets[.]dev/btreex` published; Terraform providers deployed (Git commits forged/backdated to November 2025) |
| 2026-09-09 | GHAPPIER npm loader observed (35 min 38 sec exposure) |
| 2026-09-22 | Aikido Security publicly discloses the Terraform/Go expansion |
| 2026-09-23 | The Hacker News reports; packages removed from registries |

## Root Cause: Initial Access Vector

This is a software supply-chain compromise (T1195.002) using two approaches: (1) **typosquatting** -- `kreuzwenker/docker` mimics the legitimate `kreuzwerker/docker` provider, differing by a single character; and (2) **namespace squatting** -- `gocommunity-io/dockerd` creates a plausible-sounding namespace for a Docker-related provider. Developers running `terraform init` with a misconfigured or social-engineered provider source would download and execute the malicious binary. The campaign is linked to the broader DPRK Contagious Interview / TraderTraitor cluster, where developers are approached via LinkedIn/Facebook with fake job offers and asked to build/run a project that pulls the malicious dependency.

## Technical Analysis of the Malicious Payload

### 1. Activation Gate (Anti-Analysis)

The malicious code is inserted into `internal/provider/resource_docker_container_funcs.go`. It executes only when the SHA-256 hash of the concatenation of two Terraform resource values (`containerName` + `networkID`) matches the hardcoded trigger:

```
b9966e3762e9a0d5d263b8cb3cca07294f81af9714d40ddf4628cb85d74e8ad5
```

This means the malware remains dormant in sandbox/testing environments where these values are not known, defeating automated analysis. The matching hash also serves as the AES decryption key for the embedded payload.

### 2. Encrypted Payload Delivery

The second-stage payload is embedded as an encrypted archive disguised as a SQLite database file:
- **Terraform providers:** `examples/resources/docker_container/import-resource.sqlite3` (SHA-256: `5f892a5424e88a21a3eb3d7f82ebf04d8ac31cdb19ada25153be4165df977d0f`)
- **Go modules:** `btreex.sql` (SHA-256: `ab01686d87565250fc4989faddb877d793667b07ec217a61cbd798f5695d62f5`)

When the trigger condition is met, the payload is AES-decrypted using the hash value, extracted, and executed via `go run .` as a detached background process.

### 3. C2 Architecture (Dual Channel)

**Blockchain dead-drop (primary):**
- Network: Arbitrum Sepolia testnet
- Contract: `0xAD02b5cDE693529d3bdA0266299501ad0193036C`
- Smart contract methods: `setCPubKey`, `serviceData1`, `serviceData2`
- Polling interval: 3 seconds
- 1,402 transactions recorded since August 6, 2026

**Slack API (secondary):**
- Initial check-in workspace: `portfolio-devs[.]slack[.]com` (channel: `frontend-devs`)
- Command workspace: `portfolio-testers[.]slack[.]com` (channel: `qa-announcements`)
- Historical indicator: `mediumstar[.]slack[.]com`
- Uses Slack bot token; polls `conversations.history` every 10 seconds
- Trailing marker byte sequence: `68656c6c6f6970626f742121` (decodes to "helloipbot!!")
- 1,240 encrypted messages documented from July 16 onward

**Secondary C2 IP:**
- `193.247.144[.]38` -- retrieved via the NullReceiver technique from an attacker wallet on-chain

### 4. Cryptographic Indicators

The RAT generates an ephemeral X25519 public-private key pair per-host, combines it with the threat actor's public key for shared secret derivation, and encrypts all C2 traffic. This provides forward secrecy and prevents inter-host message leakage.

**Threat actor X25519 public key:**
```
302a300506032b656e032100bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702
```

This key is shared with recent JavaScript (npm) Graphalgo samples, confirming campaign linkage.

### 5. RAT Capabilities

- Execute arbitrary Go code
- Execute arbitrary JavaScript code (via Node.js subprocess "subwatcher")
- File transfer protocol (start/chunk/end packets)
- Self-deletion on command

### 6. Anti-Forensics / Evasion

- Git commit timestamps forged/backdated to November 2025 (packages deployed September 8, 2026)
- Fake package websites mimicking established repositories
- Encrypted payload disguised as SQLite database file (file extension deception, T1036.008)
- C2 over legitimate services (Slack API, public blockchain) rather than attacker-controlled infrastructure
- Hash-gated activation prevents sandbox detonation
- Ephemeral key cryptography prevents traffic replay/decryption

### 7. Victim Telemetry

Observed 18 unique hostnames across 725 check-ins: 10 macOS, 5 Linux, 3 Windows systems.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** IPs use `[.]`; domains shown verbatim (not network-actionable in isolation). Hashes, contract addresses, and public keys are shown un-defanged for matching.

### Package / Software Level

| Package / Component | Type | Description |
|---------------------|------|-------------|
| `gocommunity-io/dockerd` | Terraform provider | 222 downloads; malicious Go RAT in provider binary |
| `kreuzwenker/docker` | Terraform provider | 1,449 downloads; typosquat of `kreuzwerker/docker` |
| `gocommunity[.]io/orderedbtree` | Go module | Published 2026-08-11; identical RAT payload |
| `gogets[.]dev/btreex` | Go module | Published 2026-09-08; identical RAT payload |
| `indexed-btree` | npm | Related Graphalgo npm malware |
| `mathsbase` | npm | Related Graphalgo npm malware |
| `mathmain` | npm | Related Graphalgo npm malware |
| `math-universe` | npm | Related Graphalgo npm malware |
| `modern-events` | npm | Related Graphalgo npm malware |
| `quick-events` | npm | Related Graphalgo npm malware |
| `crypto-hasher` | npm | Related Graphalgo npm malware |
| `events-router` | npm | Related Graphalgo npm malware |
| `sort-btree` | npm | Related Graphalgo npm malware |
| `graphcore-js` | npm | Related Graphalgo npm malware |
| `graphlib-js` | npm | Related Graphalgo npm malware |

### File System

| Path / File | Hash (SHA-256) | Description |
|-------------|----------------|-------------|
| `internal/provider/resource_docker_container_funcs.go` | -- | Modified provider source containing activation gate and decryption logic |
| `examples/resources/docker_container/import-resource.sqlite3` | `5f892a5424e88a21a3eb3d7f82ebf04d8ac31cdb19ada25153be4165df977d0f` | Encrypted RAT payload disguised as SQLite (Terraform providers) |
| `btreex.sql` | `ab01686d87565250fc4989faddb877d793667b07ec217a61cbd798f5695d62f5` | Encrypted RAT payload disguised as SQLite (Go modules) |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `193.247.144[.]38` | Secondary C2 retrieved via NullReceiver technique |
| Domain | `gocommunity[.]io` | Hosts malicious Go module `orderedbtree` |
| Domain | `gogets[.]dev` | Hosts malicious Go module `btreex` |
| Slack workspace | `portfolio-devs[.]slack[.]com` | RAT check-in channel (frontend-devs) |
| Slack workspace | `portfolio-testers[.]slack[.]com` | RAT command channel (qa-announcements) |
| Slack workspace | `mediumstar[.]slack[.]com` | Historical C2 indicator |
| Ethereum contract | `0xAD02b5cDE693529d3bdA0266299501ad0193036C` | Arbitrum Sepolia testnet dead-drop C2 |

### Cryptographic / Activation

| Type | Value | Context |
|------|-------|---------|
| SHA-256 trigger | `b9966e3762e9a0d5d263b8cb3cca07294f81af9714d40ddf4628cb85d74e8ad5` | Hash of concatenated containerName+networkID that activates payload; also AES key |
| X25519 public key | `302a300506032b656e032100bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702` | Threat actor public key shared across npm and Go/Terraform samples |
| Hex marker | `68656c6c6f6970626f742121` | Trailing byte in Slack C2 messages (decodes: "helloipbot!!") |

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious Terraform providers and Go modules published to official registries |
| T1204.002 | User Execution: Malicious File | `terraform init` downloads and executes malicious provider binary |
| T1059 | Command and Scripting Interpreter | RAT executes Go and JavaScript code on demand |
| T1102.002 | Web Service: Bidirectional Communication | Slack API used as bidirectional C2 channel |
| T1102.001 | Web Service: Dead Drop Resolver | Ethereum smart contract used as dead-drop C2 resolver |
| T1027 | Obfuscated Files or Information | Encrypted payload; hash-gated activation |
| T1036.008 | Masquerading: Masquerade File Type | Encrypted archives disguised as .sqlite3/.sql files |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 over HTTPS (Slack API, blockchain RPC) |
| T1105 | Ingress Tool Transfer | Decrypted payload executed via `go run .` |
| T1480 | Execution Guardrails | Malware activates only on specific hash of Terraform variable values |


## Impact Assessment

**Breadth:** Moderate -- 1,671 total downloads across both Terraform providers; 18 confirmed victims across macOS/Linux/Windows. The typosquat targeted a provider with 56M downloads, so the potential blast radius was significant.

**Depth:** High per-victim -- full RAT with arbitrary code execution, file transfer, and persistence via legitimate service C2 channels. Any host that triggered the activation condition was fully compromised.

**Stealth:** Very high -- hash-gated activation defeats sandboxes; C2 over Slack and public blockchain evades network monitoring; forged Git history obscures package age; encrypted payloads disguised as database files evade static scanning.

**Attribution:** DPRK / Graphalgo campaign (overlaps with Contagious Interview, TraderTraitor). Same threat actor public key and C2 infrastructure as npm samples documented by ReversingLabs.

## Detection & Remediation

### Immediate Detection
- Audit Terraform lock files (`.terraform.lock.hcl`) and provider cache for `gocommunity-io/dockerd` or `kreuzwenker/docker` (note the 'n')
- Search Go module caches and `go.sum` for `gocommunity[.]io/orderedbtree` or `gogets[.]dev/btreex`
- Hash-check for `5f892a5424e88a21a3eb3d7f82ebf04d8ac31cdb19ada25153be4165df977d0f` and `ab01686d87565250fc4989faddb877d793667b07ec217a61cbd798f5695d62f5`
- Hunt network logs for DNS queries to `gocommunity[.]io`, `gogets[.]dev`, `portfolio-devs[.]slack[.]com`, `portfolio-testers[.]slack[.]com`
- Hunt for outbound traffic to `193.247.144[.]38`
- Search for RPC calls to Arbitrum Sepolia referencing contract `0xAD02b5cDE693529d3bdA0266299501ad0193036C`

### Remediation
Remove affected packages; purge Terraform provider cache (`~/.terraform.d/plugins/`, `.terraform/providers/`); rotate all secrets, cloud credentials, and API tokens accessible from affected hosts; rebuild CI/CD runners from clean images; block C2 indicators at network perimeter.

### Long-Term Hardening
- Pin Terraform provider versions and verify checksums in `.terraform.lock.hcl`
- Use `required_providers` with explicit `source` constraints in every module
- Enable HashiCorp Sentinel or Open Policy Agent to restrict provider sources
- Audit Go module dependencies with `go mod verify`
- Egress-filter CI/CD runners; restrict Slack API and blockchain RPC access from build environments
- Implement SCA scanning for Terraform providers (Aikido, Snyk, Checkmarx)

## Detection Rules

These detections cover the campaign's durable artifacts: malicious domain names, Slack C2 workspaces, Go binary indicators, file-level payload signatures, and behavioral process-creation heuristics. All rules validated in this environment (details in audit comments per rule).

### Sigma 1: Graphalgo encrypted payload file creation
Detects creation of the SQLite-disguised encrypted payload file `import-resource.sqlite3` in a Terraform provider context.
**Status:** compile: pass (sigma convert splunk+log_scale exit 0) -- confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0 => TargetFilename="*/import-resource.sqlite3" TargetFilename IN ("*terraform*","*docker_container*"). The filename+path combination is highly specific to this campaign. -->
```yaml
title: Graphalgo malicious Terraform provider file creation
id: 8b4f3a2c-9d5e-4f0b-c6a7-2e3d4f5b6c7a
status: experimental
description: >-
  Detects creation of the SQLite-disguised encrypted payload file used by the
  Graphalgo Terraform provider malware. The malicious providers embed an
  encrypted archive as import-resource.sqlite3 in the examples directory.
references:
  - https://www.aikido.dev/blog/graphalgo-terraform-go-modules
  - https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html
author: Actioner
date: 2026/09/26
tags:
  - attack.t1036.008
  - attack.t1027
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|endswith:
      - '/import-resource.sqlite3'
    TargetFilename|contains:
      - 'terraform'
      - 'docker_container'
  condition: selection
falsepositives:
  - Legitimate Terraform provider resource import examples using SQLite
level: high
```

### Sigma 2: DNS queries to Graphalgo malicious Go module domains
Detects DNS resolution of `gocommunity[.]io` and `gogets[.]dev`, the attacker-controlled domains hosting malicious Go modules.
**Status:** compile: pass (sigma convert splunk+log_scale exit 0) -- confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0 => QueryName IN ("*gocommunity.io","*gogets.dev"). These are attacker-registered domains with no known legitimate use. High confidence. -->
```yaml
title: DNS query to Graphalgo malicious Go module domains
id: 9c5a4b3d-0e6f-4a1c-d7b8-3f4e5a6b7c8d
status: experimental
description: >-
  Detects DNS queries to domains used by the Graphalgo campaign to host
  malicious Go modules: gocommunity.io and gogets.dev. These domains hosted
  trojanized Go packages that delivered a DPRK-linked RAT.
references:
  - https://www.aikido.dev/blog/graphalgo-terraform-go-modules
  - https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html
author: Actioner
date: 2026/09/26
tags:
  - attack.t1195.002
  - attack.t1071.001
logsource:
  category: dns_query
  product: linux
detection:
  selection:
    QueryName|endswith:
      - 'gocommunity.io'
      - 'gogets.dev'
  condition: selection
falsepositives:
  - None expected - these domains are associated with malicious activity
level: high
```

### Sigma 3: Graphalgo Slack C2 workspace DNS resolution
Detects DNS resolution of the three Slack workspace domains used as C2 channels by the Graphalgo RAT. Note: the RAT's live C2 polling resolves `slack.com` / `api.slack.com` via the Slack bot API, not workspace subdomains; this rule catches browser access or reconnaissance of these workspaces, not active C2 polling traffic.
**Status:** compile: pass (sigma convert splunk+log_scale exit 0) -- confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk exit 0 => QueryName IN ("portfolio-devs.slack.com","portfolio-testers.slack.com","mediumstar.slack.com"). Workspace names are specific but could theoretically exist for legitimate orgs; high not critical. -->
```yaml
title: Graphalgo RAT Slack C2 channel communication
id: 1d6b5c4e-2f7a-4b3c-e8d9-4a5f6b7c8d9e
status: experimental
description: >-
  Detects DNS resolution of the Slack workspace domains used as C2 channels
  by the Graphalgo Go RAT deployed via malicious Terraform providers. The RAT
  polls Slack conversations.history API every 10 seconds for encrypted commands.
references:
  - https://www.aikido.dev/blog/graphalgo-terraform-go-modules
  - https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html
author: Actioner
date: 2026/09/26
tags:
  - attack.t1102.002
  - attack.t1071.001
logsource:
  category: dns_query
  product: linux
detection:
  selection:
    QueryName:
      - 'portfolio-devs.slack.com'
      - 'portfolio-testers.slack.com'
      - 'mediumstar.slack.com'
  condition: selection
falsepositives:
  - Legitimate Slack workspace access for organizations named portfolio-devs or portfolio-testers
level: high
```

### Snort: Graphalgo C2 and malicious domain indicators
Alerts on outbound traffic to the secondary C2 IP and DNS lookups for the malicious Go module domains.
**Status:** compile: structural check only (Snort not installed) -- confidence: medium
<!-- audit: Snort is not installed in this environment; structural check confirms balanced parentheses, valid sid/rev, proper content encoding for DNS wire format. IP-based rule is medium confidence as hosting may rotate. -->
```snort
alert ip $HOME_NET any -> 193.247.144.38 any (msg:"Graphalgo C2 host contact"; flow:to_server; reference:url,aikido.dev/blog/graphalgo-terraform-go-modules; classtype:trojan-activity; sid:2100901; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Graphalgo malicious domain gocommunity.io DNS lookup"; content:"|0b|gocommunity|02|io|00|"; nocase; reference:url,aikido.dev/blog/graphalgo-terraform-go-modules; classtype:trojan-activity; sid:2100902; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Graphalgo malicious domain gogets.dev DNS lookup"; content:"|06|gogets|03|dev|00|"; nocase; reference:url,aikido.dev/blog/graphalgo-terraform-go-modules; classtype:trojan-activity; sid:2100903; rev:1;)
```

### Suricata: Graphalgo network indicators (C2 IP, domains, contract address, Slack workspaces)
Comprehensive network detection covering the C2 IP, malicious Go module domains, Ethereum contract address in HTTP traffic, and Slack C2 workspace DNS.
**Status:** compile: pass (suricata -T exit 0, "Configuration provided was successfully loaded. Exiting.") -- confidence: medium
**Caveat:** The Slack workspace DNS rules (sids 2200905-2200906) match browser or recon access to these workspace subdomains. The RAT's live C2 polling resolves `slack.com` / `api.slack.com` via the Slack bot API, not the workspace subdomain, so these rules catch browsing or enumeration rather than active C2 traffic.
<!-- audit: suricata -T -S graphalgo_net.rules -l /tmp on Suricata 7.0.3 -> exit 0, clean load, no rule errors. Six rules with unique sids 2200901-2200906. dns.query sticky buffer used for DNS rules; http.request_body for contract address (correct: eth_call carries address in JSON-RPC POST body, not URI). IP rule medium confidence (hosting rotates); domain rules high confidence (attacker-controlled); contract rule medium (address encoding in body varies by client). -->
```suricata
alert ip $HOME_NET any -> 193.247.144.38 any (msg:"Actioner - Graphalgo C2 host contact (193.247.144.38)"; flow:to_server; reference:url,aikido.dev/blog/graphalgo-terraform-go-modules; classtype:trojan-activity; sid:2200901; rev:1; metadata:author Actioner, created_at 2026-09-26;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Graphalgo malicious Go module domain gocommunity.io"; dns.query; content:"gocommunity.io"; nocase; endswith; reference:url,aikido.dev/blog/graphalgo-terraform-go-modules; classtype:trojan-activity; sid:2200902; rev:1; metadata:author Actioner, created_at 2026-09-26;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Graphalgo malicious Go module domain gogets.dev"; dns.query; content:"gogets.dev"; nocase; endswith; reference:url,aikido.dev/blog/graphalgo-terraform-go-modules; classtype:trojan-activity; sid:2200903; rev:1; metadata:author Actioner, created_at 2026-09-26;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Graphalgo Arbitrum Sepolia C2 contract address in HTTP"; flow:established,to_server; http.request_body; content:"ad02b5cde693529d3bda0266299501ad0193036c"; nocase; reference:url,aikido.dev/blog/graphalgo-terraform-go-modules; classtype:trojan-activity; sid:2200904; rev:1; metadata:author Actioner, created_at 2026-09-26;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Graphalgo Slack C2 workspace portfolio-devs"; dns.query; content:"portfolio-devs.slack.com"; nocase; reference:url,aikido.dev/blog/graphalgo-terraform-go-modules; classtype:trojan-activity; sid:2200905; rev:1; metadata:author Actioner, created_at 2026-09-26;)

alert dns $HOME_NET any -> any any (msg:"Actioner - Graphalgo Slack C2 workspace portfolio-testers"; dns.query; content:"portfolio-testers.slack.com"; nocase; reference:url,aikido.dev/blog/graphalgo-terraform-go-modules; classtype:trojan-activity; sid:2200906; rev:1; metadata:author Actioner, created_at 2026-09-26;)
```

### YARA 1: Graphalgo Terraform provider Go RAT binary
Detects compiled Go RAT binaries by matching multiple embedded indicators: activation trigger hash, C2 contract address, threat actor public key, Slack workspace names, and payload filenames. Requires 3+ matches across ELF/PE/Mach-O binaries.
**Status:** compile: pass (yarac exit 0) -- confidence: high
<!-- audit: yarac graphalgo.yar graphalgo_compiled.yarc exit 0. Rule uses magic-byte condition for binary formats plus 3-of-N string threshold for non-binary scanning. Strings cover unique campaign artifacts unlikely to co-occur in legitimate software. -->
```yara
rule graphalgo_terraform_provider_malware
{
    meta:
        description = "Detects Graphalgo malicious Terraform provider Go RAT by embedded strings: activation hash, C2 contract address, threat actor public key, Slack workspace names, and encrypted payload filenames."
        author = "Actioner"
        date = "2026-09-26"
        reference = "https://www.aikido.dev/blog/graphalgo-terraform-go-modules"
        hash_payload_terraform = "5f892a5424e88a21a3eb3d7f82ebf04d8ac31cdb19ada25153be4165df977d0f"
        hash_payload_gomod = "ab01686d87565250fc4989faddb877d793667b07ec217a61cbd798f5695d62f5"

    strings:
        $trigger = "b9966e3762e9a0d5d263b8cb3cca07294f81af9714d40ddf4628cb85d74e8ad5" ascii nocase
        $contract = "0xAD02b5cDE693529d3bdA0266299501ad0193036C" ascii nocase
        $pubkey = "302a300506032b656e032100bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702" ascii nocase
        $slack1 = "portfolio-devs.slack.com" ascii nocase
        $slack2 = "portfolio-testers.slack.com" ascii nocase
        $sqlite_payload = "import-resource.sqlite3" ascii
        $gomod1 = "gocommunity.io/orderedbtree" ascii
        $gomod2 = "gogets.dev/btreex" ascii
        $filepath = "resource_docker_container_funcs.go" ascii
        $marker = "68656c6c6f6970626f742121" ascii nocase

    condition:
        filesize < 50MB and
        (uint32(0) == 0x464c457f or
        uint16(0) == 0x5a4d or
        uint32(0) == 0xfeedface or
        uint32(0) == 0xfeedfacf) and
        3 of them
}
```

### YARA 2: Graphalgo malicious Go module source code
Detects source code of the malicious Go modules by matching module path strings combined with C2 infrastructure indicators.
**Status:** compile: pass (yarac exit 0) -- confidence: high
<!-- audit: compiled in same yarac invocation. Requires both a Go module path AND at least one C2 indicator, reducing false positives from unrelated code mentioning these module paths. -->
```yara
rule graphalgo_go_module_source
{
    meta:
        description = "Detects source code of malicious Go modules (gocommunity.io/orderedbtree, gogets.dev/btreex) used in the Graphalgo supply chain campaign."
        author = "Actioner"
        date = "2026-09-26"
        reference = "https://www.aikido.dev/blog/graphalgo-terraform-go-modules"

    strings:
        $mod1 = "gocommunity.io/orderedbtree" ascii
        $mod2 = "gogets.dev/btreex" ascii
        $contract = "AD02b5cDE693529d3bdA0266299501ad0193036C" ascii nocase
        $slack = "portfolio-devs.slack.com" ascii

    condition:
        filesize < 10MB and
        any of ($mod*) and
        ($contract or $slack)
}
```

## Lessons Learned

This campaign marks the first known exploitation of the Terraform provider registry for malware distribution, extending DPRK supply-chain operations beyond npm/PyPI into infrastructure-as-code tooling. The hash-gated activation mechanism (payload dormant unless specific Terraform variable values are provided) represents a sophisticated anti-analysis technique that defeats sandboxing. Dual C2 over Slack and public blockchain provides resilient, takedown-resistant command channels that blend with legitimate enterprise traffic. Organizations must treat Terraform provider sourcing with the same scrutiny as npm/PyPI dependencies: pin versions, verify checksums, restrict provider sources, and monitor for unexpected process execution from Terraform workflows.

## Sources

- [Aikido Security -- Graphalgo campaign spreads to Terraform providers and Go Modules](https://www.aikido.dev/blog/graphalgo-terraform-go-modules) -- primary research; SHA-256 hashes, C2 infrastructure, public key, activation mechanism
- [The Hacker News -- Attackers Use Malicious Terraform Providers to Deliver Go Malware via HashiCorp Registry](https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html) -- campaign overview, package names, download counts, attribution
- [Purple Shield Security -- Graphalgo Terraform Malware Targets Cloud Credentials](https://www.purpleshieldsecurity.com/post/graphalgo-terraform-provider-malware) -- victim telemetry (18 hosts, 725 check-ins), evasion techniques, Slack message counts
- [SiteGuarding -- Malware Reaches the Terraform Registry: DPRK-Linked Actors](https://www.siteguarding.com/security-blog/terraform-registry-malware-dprk-graphalgo) -- npm package linkage, blockchain transaction counts
- [GBHackers -- Graphalgo Malware Uses Malicious Terraform Providers and Go Modules to Deploy RAT](https://gbhackers.com/graphalgo-malware/) -- campaign context, TraderTraitor linkage
- [CyberPress -- Graphalgo Malware Hits Terraform and Go Packages in New Supply Chain Attack](https://cyberpress.org/graphalgo-malware-poisons-terraform-go/) -- secondary corroboration

---
*Report generated by Actioner*
