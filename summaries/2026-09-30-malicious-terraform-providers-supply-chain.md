# Technical Analysis Report: Malicious Terraform Providers Supply-Chain Attack (2026-09-30)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-09-30
Version: 1.1 FINAL

## Executive Summary

North Korean (DPRK) threat actors are conducting a multi-vector supply-chain campaign distributing Go-based malware through HashiCorp's official Terraform provider registry -- the first documented abuse of this centralized IaC distribution channel. Two malicious Terraform providers (`gocommunity-io/dockerd` with 222 downloads and `kreuzwenker/docker` with 1,449 downloads, typosquatting the legitimate `kreuzwerker/docker` provider with 56 million downloads) and two Go modules (`gocommunity.io/orderedbtree`, `gogets.dev/btreex`) deliver a Go-based implant using Ethereum Arbitrum Sepolia testnet smart contracts and Slack workspace channels as dual C2 channels. The malware supports remote Go and JavaScript code execution and self-deletion.

In a parallel campaign, the DPRK-aligned TraderTraitor group (aka UNC4899/Jade Sleet/PUKCHONG) deploys ARM64 Rust backdoors FLATROOF and ROOFDECK via weaponized `.terraform.lock.hcl` files pointing to typosquatted HashiCorp registry domains (`registry.hashicorp-aws[.]com`, `registry.hashicorp-aws[.]io`, `registry.hashicorp-terraform[.]io`). Both campaigns target DevOps engineers through fake job interview social engineering. The Graphalgo campaign traces back to February 2026, with 18 known victims across Windows, Linux, and macOS.

## Background: Terraform Provider Registry as Attack Surface

HashiCorp's Terraform Registry (`registry.terraform.io`) is the centralized distribution point for Terraform providers -- plugins that manage resources across cloud and infrastructure platforms. When a developer runs `terraform init`, the CLI downloads provider binaries specified in configuration files from the registry, trusting the registry's namespace system for authenticity. The `.terraform.lock.hcl` file pins provider versions and hashes, but can be manipulated to redirect downloads to attacker-controlled registries. A malicious provider binary executes with the same privileges as the Terraform process itself, making this an attractive supply-chain vector for code execution on developer workstations and CI/CD pipelines.

The legitimate `kreuzwerker/docker` provider has over 56 million downloads, making it a high-value typosquatting target. The Graphalgo campaign represents the first documented case of malware distribution through the official HashiCorp registry itself, while TraderTraitor's approach weaponizes the lock file mechanism to redirect to fake registries.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-02-XX | ReversingLabs first documents Graphalgo campaign targeting npm packages |
| 2026-03-18 | TraderTraitor FLATROOF/ROOFDECK backdoors present on disk at Indian IT victim |
| 2026-03-29 05:00:53 | Both TraderTraitor implants launched via Cursor IDE opening weaponized workspace |
| 2026-04-XX | Graphalgo campaign origins traced to `modern-events` npm package |
| 2026-04-13 | Victim developer clones `terraform-candidate-repo` from GitHub |
| 2026-04-20 | TraderTraitor deploys stripped ROOFDECK variant; deletes original implants |
| 2026-06-01 | Final TraderTraitor C2 beacon observed at Indian IT victim |
| 2026-07-16 | First Graphalgo test check-in via Slack (hostname: "Frank") |
| 2026-08-06 | Blockchain smart contract activity begins (1,402 transactions recorded) |
| 2026-08-11 | Go module `gocommunity.io/orderedbtree` published |
| 2026-08-28 | Coder registry exfiltration domain `www.coder-infra[.]com` registered |
| 2026-08-31 | Coder registry compromise window 07:35-21:45 UTC |
| 2026-09-01 | Coder advisory GHSA-vx42-ghc9-gw65 published |
| 2026-09-08 | Go module `gogets.dev/btreex` published |
| 2026-09-09 | Malicious npm `@dforge-core/dforge-mcp` v0.2.21 live for 35 min 38 sec |
| 2026-09-18 | SentinelOne publishes TraderTraitor/FLATROOF/ROOFDECK analysis |
| 2026-09-22 | Aikido Security publishes Graphalgo Terraform/Go module analysis |
| 2026-09-23 | The Hacker News reports on malicious Terraform providers campaign |

## Root Cause: Supply-Chain Injection via Registry Abuse and Social Engineering

**Graphalgo Campaign:** The attackers published typosquatted Terraform providers (`kreuzwenker/docker` mimicking `kreuzwerker/docker`) and entirely new malicious providers (`gocommunity-io/dockerd`) to the official HashiCorp Terraform registry. These providers embed an activation trigger in `/internal/provider/resource_docker_container_funcs.go` that only executes when the SHA256 hash of concatenated `containerName` and `networkID` Terraform variables matches a specific value (`b9966e3762e9a0d5d263b8cb3cca07294f81af9714d40ddf4628cb85d74e8ad5`). Victims are recruited through fake job interviews on LinkedIn and Facebook, posing as non-existent Web3 companies, and asked to complete coding tasks using GitHub repositories that introduce the malicious dependency.

**TraderTraitor Campaign:** Weaponized GitHub repositories (`terraform-candidate-repo`, `gtn-candidate-repo`, `Northwind-IAC`, `novacart-interview`) contain modified `.terraform.lock.hcl` files that redirect `terraform init` to attacker-controlled registries on typosquatted domains. These fake registries serve malicious provider binaries that deploy FLATROOF and ROOFDECK backdoors.

**Coder Registry Compromise (Related):** Attackers compromised `registry.coder[.]com` by inserting unauthorized IPs into the Cloudflare server pool. Malicious Terraform modules contained injected `data "external"` blocks executing credential-harvesting scripts during provisioning.

## Technical Analysis of the Malicious Payload

### 1. Dependency Injection -- Terraform Provider and Go Module Delivery

**Malicious Terraform Providers (HashiCorp Registry):**
- `gocommunity-io/dockerd` (222 downloads) -- entirely new malicious provider
- `kreuzwenker/docker` (1,449 downloads) -- typosquat of `kreuzwerker/docker`

Both providers contain hidden entry points in `resource_docker_container_funcs.go`. The activation gate uses SHA256: the hash of `containerName + networkID` must equal `b9966e3762e9a0d5d263b8cb3cca07294f81af9714d40ddf4628cb85d74e8ad5`. This hash doubles as an AES key to decrypt a file path within the package, unzip contents, AES-decrypt each file, and execute decrypted Go code via a detached `go run .` command.

**Malicious Go Modules:**
- `gocommunity.io/orderedbtree` (published August 11, 2026)
- `gogets.dev/btreex` (published September 8, 2026)

Go modules use a secondary trigger based on a specific price integer value rather than the hash-based gate in the Terraform providers.

**Malicious npm Packages (Cross-ecosystem reach):**
- `indexed-btree`, `mathsbase`, `mathmain`, `math-universe`, `modern-events`, `quick-events`, `crypto-hasher`, `events-router`, `sort-btree`, `graphcore-js`, `graphlib-js`
- `@dforge-core/dforge-mcp` v0.2.21 (live Sep 9, 2026 for 35 min 38 sec)

### 2. Go Malware Implant (Graphalgo Payload)

Upon activation, the decrypted payload runs as a Go process with the following capabilities:
- **Remote code execution**: supports execution of Go code (via `go run`) and JavaScript (via `node`)
- **Ephemeral key generation**: generates asymmetric key pairs for payload obfuscation
- **Self-deletion**: C2 commands can trigger full removal
- **Trailing marker**: binary contains byte sequence `68656c6c6f6970626f742121` (decodes to "helloipbot!!")
- **Shared public key**: `302a300506032b656e032100bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702` (links npm and Terraform payloads)

**File Hashes (SHA256):**

| Artifact | SHA256 |
|----------|--------|
| `import-resource.sqlite3` | `5f892a5424e88a21a3eb3d7f82ebf04d8ac31cdb19ada25153be4165df977d0f` |
| `btreex.sql` | `ab01686d87565250fc4989faddb877d793667b07ec217a61cbd798f5695d62f5` |
| Trigger hash (Terraform) | `b9966e3762e9a0d5d263b8cb3cca07294f81af9714d40ddf4628cb85d74e8ad5` |

### 3. C2 Infrastructure

**Blockchain Dead Drops (Primary):**
- **Network**: Arbitrum Sepolia testnet
- **Smart contract**: `0xAD02b5cDE693529d3bdA0266299501ad0193036C`
- **Methods**: `setCPubKey`, `serviceData1`, `serviceData2`
- **Poll interval**: 3 seconds
- **Activity**: 1,402 transactions since August 6, 2026
- **Secondary network**: Ethereum Sepolia testnet

**Slack C2 (Secondary):**
- `portfolio-devs[.]slack[.]com` (channel: `frontend-devs`) -- check-in
- `portfolio-testers[.]slack[.]com` (channel: `qa-announcements`) -- secondary
- `mediumstar[.]slack[.]com` (historical)
- **API endpoint**: `conversations.history`
- **Activity**: 725 plaintext check-in messages, 1,240 encrypted messages since July 16

**TraderTraitor C2 Infrastructure:**

| Domain | IP | Role |
|--------|-----|------|
| `technicais[.]sytes[.]net` | `176.97.114[.]232` | FLATROOF C2 |
| `storage.hubpage[.]cloud` | `45.11.59[.]140` | ROOFDECK C2 |
| `grenight[.]com` | `85.137.56[.]245` | ROOFDECK C2 (post-LayerZero) |
| N/A | `85.137.56[.]10` | Staging server |
| N/A | `193.247.144[.]38` | Graphalgo infrastructure |

**Nostr Relays (ROOFDECK dead-drop resolution):**
- `wss://relay.damus[.]io`
- `wss://nos[.]lol`
- `wss://relay.nostr[.]band`
- `wss://nostr[.]wine`

**TraderTraitor Typosquatted Registries:**
- `registry.hashicorp-aws[.]com`
- `registry.hashicorp-aws[.]io`
- `registry.hashicorp-terraform[.]io`

**Coder Compromise Infrastructure:**
- Exfiltration domain: `www.coder-infra[.]com`
- Collection IP: `199.91.220[.]205`
- Exfiltration endpoint: `hxxp://www.coder-infra[.]com/cli/check` (header: `X-CLI-Token`)

### 4. Platform-Specific Behavior

#### macOS (TraderTraitor)

**FLATROOF (macOS.Gaslight):**
- ARM64 Rust binary deployed as `SystemUpdate` to `~/Library/com.apple.iTunesCloud/`
- SHA-1: `02df07a173ab03b82a4fb6a08973fff8b1467f28`
- Disables Gatekeeper via `spctl`
- Harvests: Chrome, Brave, Firefox, Safari browser data; terminal histories; installed apps; process snapshots; system profiles; raw `login.keychain-db` copies
- Exfiltrates via Telegram bot token
- C2: `technicais.sytes[.]net`

**ROOFDECK:**
- ARM64 Rust binary deployed as `iSync` to `~/Library/com.apple.internal.ck/`
- SHA-1: `c491d477dbe0ae04e9aed9dbe237144c03f73ec4`
- Stripped variant (`loginwindow`): SHA-1 `5728b11d30586bbfc1d8bd12df1c722a06e767a2`
- Persistence: LaunchAgent plist at `~/Library/LaunchAgents/loginwindow.plist` with `com.*` identifier prefix and `--type=renderer` masquerade parameter
- HTTPS C2 with custom TLS certificate pinning (SHA-256: `4b2d3e8ccce8920a6d01e7d02b84236545a20e5f754b3eec253f8b416b731daa`)
- Tasking endpoint: `/app_version`
- Authentication: RSA-2048 signed commands verified before decryption
- Dead-drop C2 resolution via Nostr protocol using operator public keys
- **Commands**: config, sleep, tasks, persist, update, destroy, run, shell, rssh, kill, cd, pwd, ls, find, cat, tail, stat, cp, mv, rm, mkdir, chmod, chown, zip, unzip, upload, wget, info, whoami, uname, uptime, lscpu, df, ps, clipboard

**Custom TLS Certificate (shared across infrastructure):**
- Subject: `CN=mkcert ub@ub-Standard-PC-Q35-ICH9-2009`
- Validity: 2025-06-20 to 2035-06-20
- Domains using it: `grenight[.]com`, `heyhay[.]online`, `galaxy-royal[.]online`, `mactroubleshoots[.]pro`, `tinklify[.]com`, and 13 others

#### Windows / Linux (Graphalgo)

The Go implant is cross-platform. Observed victim distribution: 3 Windows, 5 Linux, 10 macOS (18 unique hostnames total).

### 5. Anti-Forensics / Evasion Techniques

- **Execution gating**: SHA256-based activation trigger ensures the malware is inert without attacker-specific Terraform variable values, evading sandbox analysis
- **Self-deletion**: C2 can command full payload removal
- **Asymmetric encryption**: ephemeral public-private key pair generation for payload obfuscation
- **Blockchain C2**: using Ethereum/Arbitrum Sepolia testnets makes C2 traffic appear as legitimate blockchain API calls
- **Nostr dead drops**: decentralized relay protocol for C2 resolution resists takedowns
- **Certificate pinning**: ROOFDECK uses custom mkcert certificates to prevent MITM inspection
- **Binary stripping**: ROOFDECK stripped variant removes debug symbols
- **Process masquerade**: `--type=renderer` argument mimics legitimate browser processes
- **LaunchAgent naming**: `loginwindow.plist` mimics macOS system processes

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)

### Package / Software Level

| Package / Component | Registry | Description |
|---------------------|----------|-------------|
| `gocommunity-io/dockerd` | Terraform Registry | Malicious Docker provider (222 downloads) |
| `kreuzwenker/docker` | Terraform Registry | Typosquat of `kreuzwerker/docker` (1,449 downloads) |
| `gocommunity.io/orderedbtree` | Go Modules | Malicious Go module (published Aug 11) |
| `gogets.dev/btreex` | Go Modules | Malicious Go module (published Sep 8) |
| `indexed-btree` | npm | Graphalgo npm payload |
| `mathsbase` | npm | Graphalgo npm payload |
| `mathmain` | npm | Graphalgo npm payload |
| `math-universe` | npm | Graphalgo npm payload |
| `modern-events` | npm | Graphalgo npm payload (origin: Apr 2026) |
| `quick-events` | npm | Graphalgo npm payload |
| `crypto-hasher` | npm | Graphalgo npm payload |
| `events-router` | npm | Graphalgo npm payload |
| `sort-btree` | npm | Graphalgo npm payload |
| `graphcore-js` | npm | Graphalgo npm payload |
| `graphlib-js` | npm | Graphalgo npm payload |
| `@dforge-core/dforge-mcp` v0.2.21 | npm | Malicious MCP package (live 35m38s Sep 9) |

### File System

| Platform | Path / Name | Hash | Description |
|----------|-------------|------|-------------|
| macOS | `~/Library/com.apple.iTunesCloud/SystemUpdate` | SHA-1: `02df07a173ab03b82a4fb6a08973fff8b1467f28` | FLATROOF backdoor |
| macOS | `~/Library/com.apple.internal.ck/iSync` | SHA-1: `c491d477dbe0ae04e9aed9dbe237144c03f73ec4` | ROOFDECK backdoor |
| macOS | `loginwindow` | SHA-1: `5728b11d30586bbfc1d8bd12df1c722a06e767a2` | Stripped ROOFDECK variant |
| macOS | `~/Library/LaunchAgents/loginwindow.plist` | N/A | ROOFDECK persistence LaunchAgent |
| Cross-platform | `import-resource.sqlite3` | SHA-256: `5f892a5424e88a21a3eb3d7f82ebf04d8ac31cdb19ada25153be4165df977d0f` | Graphalgo payload artifact |
| Cross-platform | `btreex.sql` | SHA-256: `ab01686d87565250fc4989faddb877d793667b07ec217a61cbd798f5695d62f5` | Graphalgo Go module artifact |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `gocommunity[.]io` | Graphalgo TA-controlled infrastructure |
| Domain | `gogets[.]dev` | Graphalgo TA-controlled infrastructure |
| Domain | `technicais.sytes[.]net` | FLATROOF C2 |
| Domain | `storage.hubpage[.]cloud` | ROOFDECK C2 |
| Domain | `grenight[.]com` | ROOFDECK C2 (post-LayerZero) |
| Domain | `heyhay[.]online` | TraderTraitor infrastructure |
| Domain | `galaxy-royal[.]online` | TraderTraitor infrastructure |
| Domain | `mactroubleshoots[.]pro` | TraderTraitor infrastructure |
| Domain | `tinklify[.]com` | TraderTraitor infrastructure |
| Domain | `registry.hashicorp-aws[.]com` | Typosquatted Terraform registry |
| Domain | `registry.hashicorp-aws[.]io` | Typosquatted Terraform registry |
| Domain | `registry.hashicorp-terraform[.]io` | Typosquatted Terraform registry |
| Domain | `www.coder-infra[.]com` | Coder compromise exfiltration domain |
| IP | `176.97.114[.]232` | FLATROOF C2 (technicais.sytes) |
| IP | `45.11.59[.]140` | ROOFDECK C2 (hubpage) |
| IP | `85.137.56[.]245` | ROOFDECK C2 (grenight) |
| IP | `85.137.56[.]10` | Staging server |
| IP | `193.247.144[.]38` | Graphalgo infrastructure |
| IP | `199.91.220[.]205` | Coder compromise collection |
| Smart Contract | `0xAD02b5cDE693529d3bdA0266299501ad0193036C` | Arbitrum Sepolia C2 contract |
| TLS Cert SHA-256 | `4b2d3e8ccce8920a6d01e7d02b84236545a20e5f754b3eec253f8b416b731daa` | ROOFDECK custom certificate |

### Behavioral

- Terraform or terraform-provider processes spawning `go` or `node` child processes
- Outbound Slack API calls (`conversations.history`) from non-browser, non-Slack-client processes
- `.terraform.lock.hcl` files referencing non-`registry.terraform.io` hosts (especially `hashicorp-aws` or `hashicorp-terraform` in the domain)
- Ethereum/Arbitrum Sepolia RPC calls at 3-second intervals from developer workstations
- LaunchAgent plists using `--type=renderer` argument (browser process masquerade)
- Outbound connections to Nostr relay WebSocket endpoints from non-Nostr-client processes

### Threat Actor GitHub Accounts

| Account | Role |
|---------|------|
| `gocommunity-io` | TA-controlled organization |
| `gogets-dev` | TA-controlled organization |
| `go-pack-tech` | Malware committer |
| `kreuzwenker` | Malware committer (typosquat account) |
| `victormmpp` | Forged commits (orderedbtree) |
| `markcary3` | Malware committer (btreex) |
| `steveb082` | TA organization member |
| `go-community-admin` | TA organization member |

### Weaponized GitHub Repositories

- `terraform-candidate-repo`
- `gtn-candidate-repo`
- `Northwind-IAC`
- `novacart-interview`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Compromise Software Supply Chain | Malicious Terraform providers published to HashiCorp registry; typosquatted Go modules; malicious npm packages |
| T1204.002 | User Execution: Malicious File | Victims execute `terraform init`/`apply` on weaponized repositories from fake job interviews |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Remote Go code execution via `go run .` launched from shell |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Remote JavaScript code execution via `node` launched from C2 commands |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS-based C2 for FLATROOF/ROOFDECK; Slack API for Graphalgo |
| T1102.002 | Web Service: Bidirectional Communication | Slack conversations.history API as C2 channel; Nostr relay protocol for dead-drop C2 |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | RSA-2048 signed C2 commands; ephemeral key pair generation |
| T1547.011 | Boot or Logon Autostart Execution: Plist Modification | ROOFDECK LaunchAgent persistence via loginwindow.plist |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | FLATROOF harvests Chrome, Brave, Firefox, Safari browser data |
| T1555.001 | Credentials from Password Stores: Keychain | FLATROOF copies raw login.keychain-db |
| T1036.004 | Masquerading: Masquerade Task or Service | loginwindow.plist name and --type=renderer argument mimic system processes |
| T1140 | Deobfuscate/Decode Files or Information | AES decryption of payload using hash-derived key |
| T1567 | Exfiltration Over Web Service | FLATROOF exfiltrates via Telegram bot; Coder compromise via X-CLI-Token header |
| T1102.001 | Web Service: Dead Drop Resolver | Blockchain smart contract (Arbitrum Sepolia) and Nostr relay dead drops for dynamic C2 resolution |

## Impact Assessment

- **Breadth**: 1,671 total downloads of malicious Terraform providers; 18 confirmed compromised hosts (3 Windows, 5 Linux, 10 macOS); loader observed in 65 public repositories across 22 GitHub accounts; Coder registry compromise affected users of versions prior to 2.37.0/2.36.4/2.35.7/2.34.9
- **Depth**: Full remote code execution on developer workstations; credential theft including browser data, keychains, SSH keys, cloud API keys, CI/CD tokens; persistent backdoor access with Nostr-based resilient C2
- **Stealth**: Hash-based activation gate renders the malicious provider inert under sandbox analysis; blockchain and Nostr C2 channels are novel and unlikely to be detected by traditional network monitoring; the malware was present in the official HashiCorp registry
- **Attribution**: DPRK-linked. Graphalgo campaign attributed to North Korean actors with overlaps to PolinRider and Contagious Interview campaigns. TraderTraitor (UNC4899/Jade Sleet/PUKCHONG) is a documented Lazarus subgroup. The LayerZero Labs breach by this group resulted in an estimated USD 292 million theft.

## Detection & Remediation

### Immediate Detection

```bash
# Check for malicious Terraform providers in local cache
find ~/.terraform.d/plugins -name "*kreuzwenker*" -o -name "*gocommunity-io*" 2>/dev/null
find .terraform/providers -name "*kreuzwenker*" -o -name "*gocommunity-io*" 2>/dev/null

# Search for typosquatted registry references in lock files
grep -r "hashicorp-aws\.\|hashicorp-terraform\.\|kreuzwenker" --include="*.lock.hcl" .

# Check for malicious Go modules in module cache
ls -la ~/go/pkg/mod/gocommunity.io/ 2>/dev/null
ls -la ~/go/pkg/mod/gogets.dev/ 2>/dev/null

# macOS: check for FLATROOF/ROOFDECK persistence
ls -la ~/Library/com.apple.iTunesCloud/ 2>/dev/null
ls -la ~/Library/com.apple.internal.ck/ 2>/dev/null
ls -la ~/Library/LaunchAgents/loginwindow.plist 2>/dev/null

# Check for hash matches on known artifacts
find / -name "import-resource.sqlite3" -o -name "btreex.sql" 2>/dev/null

# Network: check for C2 domain resolution
grep -E "gocommunity\.io|gogets\.dev|technicais\.sytes|hubpage\.cloud|grenight\.com|hashicorp-aws|hashicorp-terraform" /var/log/dns* /var/log/syslog 2>/dev/null
```

### Remediation

1. **Containment**: Immediately quarantine any workstation where malicious providers or lock file references are found. Revoke all cloud credentials, SSH keys, API tokens, and CI/CD secrets accessible from affected machines.
2. **Eradication**: Remove malicious Terraform providers from local caches (`~/.terraform.d/plugins`, `.terraform/providers`). Remove malicious Go modules (`go clean -modcache`). On macOS, remove FLATROOF/ROOFDECK persistence artifacts and binaries.
3. **Recovery**: Rotate all secrets that were accessible from compromised workstations. Audit CI/CD pipelines for unauthorized changes. Review Terraform state files for unauthorized resource modifications. Update Coder to patched versions (2.37.0+, 2.36.4+, 2.35.7+, 2.34.9+).
4. **Secret Rotation**: Prioritize cloud provider credentials (AWS IAM keys, GCP service account keys, Azure SPN secrets), GitHub PATs, npm tokens, Docker Hub credentials, database passwords, and OIDC tokens.

### Long-Term Hardening

- **Pin provider sources**: Use `required_providers` blocks with explicit `source` attributes and version constraints. Verify provider namespaces match expected publishers.
- **Lock file integrity**: Add `.terraform.lock.hcl` to code review gates. Alert on changes to provider source URLs, especially non-`registry.terraform.io` hosts.
- **Provider hash verification**: Use `terraform providers lock` to generate and verify checksums. Enforce `h1:` and `zh:` hashes in lock files.
- **Network monitoring**: Block or alert on DNS resolution to known typosquatted registry domains. Monitor for Arbitrum/Ethereum Sepolia testnet RPC calls from developer workstations.
- **CI/CD isolation**: Run `terraform init`/`plan`/`apply` in ephemeral, network-restricted containers with no access to developer credentials.
- **Dependency scanning**: Integrate supply-chain security tools (e.g., Aikido, Socket, Snyk) that monitor Terraform providers, Go modules, and npm packages for suspicious behavior.

## Detection Rules

<!-- revision: v1.1 — applied critic verdict NEEDS-REVISION. Dropped: Sigma Slack C2 (generic Slack API FP), Suricata sid:2100107 (same), Snort sid:2100201 (same), Snort sid:2100202 (generic /app_version URI). Fixed: Sigma process-creation confidence high→medium (TTP rules); Linux rule title narrowed to "Linux" only (product: linux excludes macOS); lock file condition OR→AND (was matching any .terraform.lock.hcl event); DNS endswith entries given leading dots; MITRE T1568.002→T1102.001, T1059→T1059.004/T1059.007; ATT&CK tags updated in rules. -->

The following rules cover the Graphalgo malicious Terraform provider delivery chain (process creation, DNS), the TraderTraitor FLATROOF/ROOFDECK binary artifacts (YARA), and known C2 domain IOCs (Suricata). Process-creation rules require Sysmon or equivalent telemetry with parent-process context; compiles does not equal fires -- verify in your pipeline.

### Sigma: Terraform Binary Spawning Unexpected Go Child (Windows)

Detects terraform or terraform-provider binaries spawning Go or Node.js child processes on Windows, indicative of the Graphalgo malicious provider executing downloaded code.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk/log_scale exit 0. TTP/behavioral rule (parent-child pattern) — confidence capped at medium per strict altitude. Field names (ParentImage, Image) match Sysmon EID 1 schema. Values use real paths, not defanged. Tags updated to T1059.004/T1059.007 subtechniques. -->

```yaml
title: Terraform Binary Spawning Unexpected Go Child Process
id: 7a3e1f42-9b8c-4d5e-af17-2c6b0e8d3f9a
status: experimental
description: >
    Detects terraform or terraform-provider binaries spawning Go compilation
    or execution processes, which may indicate a malicious Terraform provider
    delivering Go malware as seen in the Graphalgo supply-chain campaign.
references:
    - https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html
    - https://www.aikido.dev/blog/graphalgo-terraform-go-modules
author: Actioner
date: 2026-09-30
tags:
    - attack.t1195.002
    - attack.t1059.004
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|contains:
            - '\terraform.exe'
            - '\terraform-provider-'
    selection_child:
        Image|endswith:
            - '\go.exe'
            - '\node.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Terraform providers that compile Go code at runtime (unlikely in production)
level: high
```

### Sigma: Terraform Provider Spawning Unexpected Child on Linux

Detects the same parent-child process pattern on Linux where Sysmon-for-Linux or auditd with process lineage is deployed.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk/log_scale exit 0. TTP/behavioral rule — confidence capped at medium. Title narrowed to "Linux" only; product: linux does not cover macOS. Sysmon-for-Linux field names. Tags updated to T1059.004/T1059.007. -->

```yaml
title: Terraform Provider Spawning Unexpected Child on Linux
id: 8b4f2a53-0c9d-4e6f-b028-3d7c1f9e4a0b
status: experimental
description: >
    Detects terraform or terraform-provider processes spawning go or node
    child processes on Linux, indicating potential malicious provider
    execution from the Graphalgo campaign targeting DevOps engineers.
references:
    - https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html
    - https://www.aikido.dev/blog/graphalgo-terraform-go-modules
author: Actioner
date: 2026-09-30
tags:
    - attack.t1195.002
    - attack.t1059.004
    - attack.t1059.007
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|contains:
            - '/terraform'
            - '/terraform-provider-'
    selection_child:
        Image|endswith:
            - '/go'
            - '/node'
    condition: selection_parent and selection_child
falsepositives:
    - Custom Terraform providers that invoke go toolchain during plan or apply
level: high
```

### Sigma: Terraform Lock File Referencing Typosquatted Registry

Detects file events on `.terraform.lock.hcl` files whose path also contains typosquatted registry domain strings, covering the TraderTraitor lock file weaponization vector.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma convert --without-pipeline -t splunk/log_scale exit 0. Critical fix: condition changed from OR to AND — the OR form matched ANY .terraform.lock.hcl file event regardless of content, producing massive FP volume. The AND requires both the lock file extension AND the typosquatted registry string in the path. file_event category requires Sysmon EID 11 or equivalent. -->

```yaml
title: Terraform Lock File Referencing Typosquatted HashiCorp Registry
id: 9c5a3b64-1d0e-4f7a-c139-4e8d2a0f5b1c
status: experimental
description: >
    Detects creation or modification of .terraform.lock.hcl files containing
    references to typosquatted HashiCorp registry domains used by TraderTraitor
    to deliver FLATROOF and ROOFDECK backdoors via malicious Terraform providers.
references:
    - https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/
author: Actioner
date: 2026-09-30
tags:
    - attack.t1195.002
logsource:
    category: file_event
detection:
    selection_file:
        TargetFilename|endswith: '.terraform.lock.hcl'
    selection_content:
        TargetFilename|contains:
            - 'hashicorp-aws'
            - 'hashicorp-terraform'
    condition: selection_file and selection_content
falsepositives:
    - Files named with hashicorp-aws or hashicorp-terraform for legitimate testing purposes
level: high
```

### Sigma: Suspicious Slack API C2 Communication from Non-Browser Process -- DROPPED

Dropped: at strict altitude, matches ANY Slack API `conversations.history` call from non-browser processes. Legitimate Slack bot integrations produce constant false positives. Campaign-specific workspace names (`portfolio-devs`, `portfolio-testers`, `mediumstar`) are available but insufficient to constrain the proxy-level rule without endpoint correlation.

### Sigma: DNS Query to Graphalgo/TraderTraitor Infrastructure Domains

Detects DNS queries to known attacker-controlled domains across both campaigns.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma convert --without-pipeline -t splunk/log_scale exit 0. Fixed: all endswith entries now have leading dots to prevent partial-match on longer domain suffixes. dns_query category maps to Sysmon EID 22. Values use real (non-defanged) domains per logsource-encoding.md. IOC-grade — rotate as new infrastructure appears. -->

```yaml
title: DNS Query to Graphalgo or TraderTraitor Infrastructure Domains
id: be7c5d86-3f2a-6b9c-e351-6a0f4c2b7d3e
status: experimental
description: >
    Detects DNS queries to known C2 and infrastructure domains associated
    with the Graphalgo supply-chain campaign and TraderTraitor DPRK operations
    targeting DevOps engineers via malicious Terraform providers.
references:
    - https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html
    - https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/
author: Actioner
date: 2026-09-30
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '.gocommunity.io'
            - '.gogets.dev'
            - '.technicais.sytes.net'
            - '.hubpage.cloud'
            - '.grenight.com'
            - '.heyhay.online'
            - '.galaxy-royal.online'
            - '.mactroubleshoots.pro'
            - '.tinklify.com'
    condition: selection
falsepositives:
    - Unlikely; these domains are attacker-controlled infrastructure
level: critical
```

### YARA: Graphalgo Go Implant Detection

Detects the Go-based Graphalgo malware by characteristic strings including Slack workspace names, blockchain smart contract address, and the "helloipbot!!" marker.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Strings are campaign-specific (Slack workspace names, contract address, shared public key, "helloipbot!!" marker) with low FP risk. filesize 50MB accommodates Go binaries. Condition OR branches allow detection on partial artifact presence. -->

```yara
rule Malware_Graphalgo_Go_Implant : graphalgo dprk supply_chain
{
    meta:
        description = "Detects Go-based Graphalgo malware distributed via malicious Terraform providers and Go modules, identified by characteristic strings related to blockchain C2 and Slack beacon channels"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://www.aikido.dev/blog/graphalgo-terraform-go-modules"
        tlp = "WHITE"
        severity = "high"

    strings:
        $magic = "helloipbot!!" ascii
        $magic_hex = { 68 65 6C 6C 6F 69 70 62 6F 74 21 21 }
        $slack1 = "portfolio-devs.slack.com" ascii
        $slack2 = "portfolio-testers.slack.com" ascii
        $slack3 = "mediumstar.slack.com" ascii
        $slack_api = "conversations.history" ascii
        $contract = "0xAD02b5cDE693529d3bdA0266299501ad0193036C" ascii
        $method1 = "setCPubKey" ascii
        $method2 = "serviceData1" ascii
        $method3 = "serviceData2" ascii
        $pubkey = "bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702" ascii
        $domain1 = "gocommunity.io" ascii
        $domain2 = "gogets.dev" ascii

    condition:
        filesize < 50MB and
        (
            $magic or $magic_hex or
            2 of ($slack*) or
            ($contract and 1 of ($method*)) or
            $pubkey or
            (1 of ($domain*) and 1 of ($slack*))
        )
}
```

### YARA: TraderTraitor FLATROOF Backdoor

Detects the FLATROOF (macOS.Gaslight) ARM64 Rust backdoor by persistence paths, C2 domain, and data harvesting indicators.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. $c2_1 alone is high-confidence given dynamic DNS sytes.net. ($path1 and $name1) specific to FLATROOF deployment. $keychain+$tg+$brave/$gatekeeper narrows browser harvesting branch. -->

```yara
rule Malware_TraderTraitor_FLATROOF : tradertraitor dprk macos
{
    meta:
        description = "Detects FLATROOF (macOS.Gaslight) ARM64 Rust backdoor deployed by TraderTraitor via weaponized Terraform repositories"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $path1 = "com.apple.iTunesCloud" ascii
        $name1 = "SystemUpdate" ascii fullword
        $c2_1 = "technicais.sytes.net" ascii
        $tg = "Telegram" ascii
        $keychain = "login.keychain-db" ascii
        $brave = "BraveSoftware" ascii
        $gatekeeper = "spctl" ascii
        $type_renderer = "--type=renderer" ascii

    condition:
        filesize < 20MB and
        (
            ($path1 and $name1) or
            $c2_1 or
            ($keychain and $tg and 1 of ($brave, $gatekeeper)) or
            ($type_renderer and $path1)
        )
}
```

### YARA: TraderTraitor ROOFDECK Backdoor

Detects the ROOFDECK ARM64 Rust backdoor by persistence paths, C2 domains, Nostr relay strings, and command set.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. Nostr relay strings alone common in legitimate clients; requiring C2 domain OR command set alongside them reduces FP. $path1+$name1 highly specific. $endpoint "/app_version" generic so requires 2+ cmd strings. -->

```yara
rule Malware_TraderTraitor_ROOFDECK : tradertraitor dprk macos
{
    meta:
        description = "Detects ROOFDECK ARM64 Rust backdoor deployed as secondary implant by TraderTraitor, featuring Nostr-based C2 and RSA-signed commands"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $path1 = "com.apple.internal.ck" ascii
        $name1 = "iSync" ascii fullword
        $c2_1 = "hubpage.cloud" ascii
        $c2_2 = "grenight.com" ascii
        $nostr1 = "relay.damus.io" ascii
        $nostr2 = "nos.lol" ascii
        $nostr3 = "relay.nostr.band" ascii
        $nostr4 = "nostr.wine" ascii
        $endpoint = "/app_version" ascii
        $cmd1 = "rssh" ascii fullword
        $cmd2 = "persist" ascii fullword
        $cmd3 = "destroy" ascii fullword
        $cmd4 = "clipboard" ascii fullword

    condition:
        filesize < 20MB and
        (
            ($path1 and $name1) or
            (1 of ($c2_*) and 1 of ($nostr*)) or
            ($endpoint and 2 of ($cmd*)) or
            (2 of ($nostr*) and 2 of ($cmd*))
        )
}
```

### Suricata: Graphalgo/TraderTraitor DNS IOC Detection

Network-level DNS rules for known C2 and typosquatted registry domains.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0. Dot-notation buffers (dns.query) confirmed valid. DNS IOC rules are high-confidence on attacker-controlled domains. Slack HTTP rule (sid:2100107) dropped — generic Slack API FP at strict altitude. -->

```suricata
alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Graphalgo C2 Domain gocommunity.io"; flow:to_server; dns.query; content:"gocommunity.io"; nocase; fast_pattern; classtype:trojan-activity; reference:url,thehackernews.com/2026/09/attackers-use-malicious-terraform.html; metadata:author Actioner, created_at 2026-09-30; sid:2100101; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to Graphalgo C2 Domain gogets.dev"; flow:to_server; dns.query; content:"gogets.dev"; nocase; fast_pattern; classtype:trojan-activity; reference:url,aikido.dev/blog/graphalgo-terraform-go-modules; metadata:author Actioner, created_at 2026-09-30; sid:2100102; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to TraderTraitor FLATROOF C2 technicais.sytes.net"; flow:to_server; dns.query; content:"technicais.sytes.net"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; metadata:author Actioner, created_at 2026-09-30; sid:2100103; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to TraderTraitor ROOFDECK C2 hubpage.cloud"; flow:to_server; dns.query; content:"hubpage.cloud"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; metadata:author Actioner, created_at 2026-09-30; sid:2100104; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to TraderTraitor ROOFDECK C2 grenight.com"; flow:to_server; dns.query; content:"grenight.com"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; metadata:author Actioner, created_at 2026-09-30; sid:2100105; rev:1;)

alert dns $HOME_NET any -> any any (msg:"Actioner - DNS Query to TraderTraitor Typosquat Registry hashicorp-aws"; flow:to_server; dns.query; content:"hashicorp-aws"; nocase; fast_pattern; classtype:trojan-activity; reference:url,sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; metadata:author Actioner, created_at 2026-09-30; sid:2100106; rev:1;)
```

### Suricata: Graphalgo Slack C2 HTTP Beacon (sid:2100107) -- DROPPED

Dropped: generic Slack API `conversations.history` match produces constant false positives from legitimate Slack integrations at strict altitude. Campaign-specific workspace names not constrainable at the HTTP layer without endpoint correlation.

### Snort: N/A

Both Snort rules dropped at strict altitude: sid:2100201 (Slack C2 beacon) matched any `conversations.history` call to `slack.com` via `http_header` content match, widening FP surface beyond the Suricata equivalent; sid:2100202 (`/app_version` tasking endpoint) matched a common URI pattern with no destination IP/domain constraint, producing massive FP volume.

## Lessons Learned

1. **IaC registries are now first-class supply-chain targets.** The Terraform Registry joins npm, PyPI, and crates.io as a vector for state-sponsored malware distribution. The unique danger is that Terraform providers execute with full process privileges during infrastructure provisioning, often in CI/CD pipelines with cloud credentials.

2. **Execution gating defeats naive sandbox analysis.** The Graphalgo payload's SHA256 hash-based activation gate means the provider appears completely benign under standard dynamic analysis. Detection must focus on behavioral indicators (child process spawning) and static analysis of provider source code, not just sandboxing binaries.

3. **Blockchain and decentralized protocols create resilient C2.** The use of Ethereum/Arbitrum Sepolia testnet smart contracts and Nostr relay dead drops for C2 resolution is a significant evasion advancement. These channels blend with legitimate developer traffic and resist traditional domain takedowns.

4. **Lock file manipulation is an undermonitored vector.** The TraderTraitor campaign's weaponization of `.terraform.lock.hcl` files demonstrates that even version-pinning mechanisms can be subverted. Code review processes should explicitly audit changes to lock files and provider source URLs.

5. **Cross-ecosystem campaign reuse accelerates reach.** The shared public key, blockchain infrastructure, and Slack C2 channels across npm, Go modules, and Terraform providers show that a single campaign infrastructure scales rapidly across package ecosystems. Defenders should correlate IOCs across all dependency management systems in use.

## Sources

- [The Hacker News - Attackers Use Malicious Terraform Providers to Deliver Go Malware via HashiCorp Registry](https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html) -- primary reporting on Graphalgo Terraform provider abuse
- [SentinelOne Labs - Don't Call Us, We'll Call Your APIs: TraderTraitor Backdoors Resurface](https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/) -- primary technical analysis of FLATROOF/ROOFDECK and weaponized Terraform lock files
- [Aikido Security - Graphalgo Campaign Spreads to Terraform Providers and Go Modules](https://www.aikido.dev/blog/graphalgo-terraform-go-modules) -- detailed IOCs, file hashes, Slack C2 workspace details, smart contract analysis
- [Cloud Security Alliance - Coder Registry Compromise Spreads Credential-Stealing Terraform Modules](https://labs.cloudsecurityalliance.org/research/csa-research-note-coder-registry-terraform-supply-chain-2026/) -- Coder registry compromise timeline and IOCs
- [GBHackers - Hackers Weaponize Terraform Lock Files to Infect DevOps Engineers With macOS Backdoors](https://gbhackers.com/terraform-lock-files/) -- TraderTraitor lock file attack vector coverage
- [SOC Prime - TraderTraitor Backdoors Target DevOps Engineers](https://socprime.com/active-threats/tradertraitor-backdoors-target-victims-outside-the-cryptocurrency-sector/) -- TraderTraitor campaign context and detection guidance

---
*Report generated by Actioner*
