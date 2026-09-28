# Technical Analysis Report: TraderTraitor FLATROOF/ROOFDECK Backdoors via Malicious Terraform Providers (2026-09-28)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-09-28
Version: 2.0

<!-- revision: v2.0 — applied critic verdict (REVISE). P0: cut Sigma Rule 1 (Terraform Init command-line detection — attacker registry domains never appear in terraform CLI args, they are read from .tf/.terraform.lock.hcl at runtime; DNS/YARA rules cover this vector); fixed T1027.002→T1027 (stripping debug symbols is not software packing). P1: cut Sigma Rule 3 (generic xattr quarantine removal — zero campaign context, wrong altitude for specific/strict; Rule 2 covers payloads); demoted Suricata SID 2026092806 and Snort SID 2026092814 /app_version URI rules to informational (common health-check endpoint, high FP in isolation); added filesize<1MB + Terraform context strings to YARA TraderTraitor_Terraform_LockFile_Poisoned. P2: removed attack.t1543.001 tag from Sigma Rule 2 (file drop, not LaunchAgent creation); renamed Attack Timeline→Attack Sequence (no concrete UTC timestamps). P3: documented FAT Mach-O limitation in YARA rule metadata; added DNS-over-TCP Snort rule variants. Removed tactic-only tags from Sigma per spec. All changed rules re-validated. -->

## Executive Summary

North Korean state-sponsored actors tracked as TraderTraitor deployed ARM64 Rust-based macOS backdoors designated FLATROOF (aka macOS.Gaslight) and ROOFDECK against a DevOps engineer at an IT services company with no cryptocurrency ties. The intrusion leveraged weaponized Terraform lock files (`.terraform.lock.hcl`) that reference fake HashiCorp-impersonating provider registries, marking the first documented abuse of Terraform infrastructure as a malware distribution vector. The attack originated through fake job interview coding challenges delivered via GitHub repositories, with multi-stage payloads culminating in persistent backdoor access using LaunchAgent persistence, Gatekeeper bypass, and advanced C2 channels including HTTPS with pinned certificates and Nostr relay-based operator discovery.

This campaign represents a significant expansion of TraderTraitor targeting beyond cryptocurrency firms to general IT infrastructure companies, and introduces a novel supply-chain vector through the Terraform provider ecosystem that DevOps and infrastructure teams should evaluate immediately.

## Background: Terraform Provider Ecosystem

Terraform by HashiCorp uses a provider registry system to download plugins that manage infrastructure resources. The `.terraform.lock.hcl` file pins provider versions and their cryptographic hashes. When a developer runs `terraform init`, Terraform resolves providers from the registry URLs specified in configuration. By substituting legitimate HashiCorp registry domains with attacker-controlled look-alikes (e.g., `registry.hashicorp-aws[.]com` instead of `registry.terraform.io`), the threat actors caused `terraform init` to fetch and execute malicious provider binaries, bypassing typical code review scrutiny since lock files are often treated as auto-generated artifacts.

## Attack Sequence

| Phase | Event |
|-------|-------|
| Pre-compromise | Threat actors establish fake company profiles with LinkedIn presences for social engineering |
| Initial contact | Target DevOps engineer approached via fake job interview for coding challenge |
| Initial access | Victim clones weaponized GitHub repo containing poisoned `.terraform.lock.hcl` |
| Stage 1 | `terraform init` fetches malicious provider from attacker-controlled registry |
| Stage 2 | FLATROOF (SystemUpdate) deployed to `~/Library/com.apple.iTunesCloud/` |
| Persistence | LaunchAgent plist installed with `--type=renderer` parameter masquerade |
| Gatekeeper bypass | `xattr -rd com.apple.quarantine` removes quarantine attributes |
| Escalation | ROOFDECK (iSync) deployed to `~/Library/com.apple.internal.ck/` |
| Post-April 20 | ROOFDECK C2 switches from `storage.hubpage[.]cloud` to `grenight[.]com` |
| Later stage | Stripped ROOFDECK variant (loginwindow) deployed to `~/Library/com.apple.appleaccountd/` |
| Data harvesting | Python module exfiltrates browser data, command histories, keychains, and credentials |

## Root Cause: Social Engineering via Fake Job Interviews + Terraform Supply Chain

The initial access vector was a social engineering operation where TraderTraitor actors posed as recruiters conducting technical interviews. The target was directed to clone a GitHub repository containing a "coding challenge" that included a weaponized `.terraform.lock.hcl` file. This lock file referenced custom Terraform provider registries on attacker-controlled domains that impersonate HashiCorp infrastructure. When the victim ran `terraform init`, Terraform resolved and executed the malicious provider binary, establishing the initial foothold without requiring any vulnerability exploitation.

Weaponized GitHub repositories identified:
- `terraform-candidate-repo`
- `gtn-candidate-repo`
- `Northwind-IAC`
- `novacart-interview`

## Technical Analysis of the Malicious Payload

### 1. Malicious Terraform Provider Delivery

The attack leveraged `.terraform.lock.hcl` files configured to resolve providers from three attacker-controlled registries that impersonate HashiCorp:

- `registry.hashicorp-aws[.]com`
- `registry.hashicorp-aws[.]io`
- `registry.hashicorp-terraform[.]io`

Running `terraform init` with these lock files causes Terraform to download and execute attacker-supplied provider binaries. This is distinct from the related campaign that used the legitimate HashiCorp Terraform Registry with malicious providers (`gocommunity-io/dockerd` and `kreuzwenker/docker`); the TraderTraitor operation used entirely spoofed registries.

### 2. FLATROOF (macOS.Gaslight) - First-Stage Backdoor

FLATROOF is an ARM64 Rust-based macOS backdoor deployed as `SystemUpdate` to `~/Library/com.apple.iTunesCloud/`. Key characteristics:

- **SHA-1:** `02df07a173ab03b82a4fb6a08973fff8b1467f28`
- **C2 Domain:** `technicais.sytes[.]net` (resolving to `176.97.114[.]232`)
- **Lock File:** Uses `$TMPDIR/tmp*.lock` for single-instance enforcement
- **Persistence:** LaunchAgent plist under `~/Library/LaunchAgents/` with `com.` prefix and `--type=renderer` parameter
- **Gatekeeper Bypass:** `xattr -rd com.apple.quarantine` applied to downloaded payload

### 3. ROOFDECK - Advanced Second-Stage Backdoor

ROOFDECK is a more capable ARM64 Rust-based macOS backdoor with advanced C2 capabilities:

- **SHA-1 (iSync variant):** `c491d477dbe0ae04e9aed9dbe237144c03f73ec4`
- **SHA-1 (loginwindow variant, stripped):** `5728b11d30586bbfc1d8bd12df1c722a06e767a2`
- **Deployed paths:**
  - `~/Library/com.apple.internal.ck/iSync`
  - `~/Library/com.apple.appleaccountd/loginwindow`
- **Configuration file:** `$HOME/.config/.repl_history`
- **IPC pipe:** `/private/tmp/.pipe-airway`

#### ROOFDECK C2 Protocol

- **Primary HTTPS C2:** Beacons to `/app_version` endpoint
- **Certificate Pinning:** Custom TLS certificate embedded in the binary (SHA-256: `4b2d3e8ccce8920a6d01e7d02b84236545a20e5f754b3eec253f8b416b731daa`)
- **Command Authentication:** RSA-2048 signed commands
- **Nostr Relay Integration:** Uses Nostr decentralized protocol relays for operator profile discovery, providing resilient C2 channel

C2 infrastructure evolved during the campaign:
- Initial: `storage.hubpage[.]cloud` (`45.11.59[.]140`)
- Post-April 20: `grenight[.]com` (`85.137.56[.]245`)
- Staging server: `85.137.56[.]10`

### 4. C2 Infrastructure

| Domain | IP | Role |
|--------|-----|------|
| `technicais.sytes[.]net` | `176.97.114[.]232` | FLATROOF primary C2 |
| `storage.hubpage[.]cloud` | `45.11.59[.]140` | ROOFDECK initial C2 |
| `grenight[.]com` | `85.137.56[.]245` | ROOFDECK rotated C2 |
| N/A | `85.137.56[.]10` | ROOFDECK staging server |

Nostr relays used for C2 operator discovery:
- `wss://relay.damus[.]io`
- `wss://nos[.]lol`
- `wss://nostr[.]mom`
- `wss://relay.snort[.]social`
- `wss://offchain[.]pub`
- `wss://relay.nostr[.]band`
- `wss://nostr.oxtr[.]dev`
- `wss://nostr[.]wine`

### 5. Anti-Forensics / Evasion Techniques

- **Apple directory masquerade:** Backdoor binaries placed in directories mimicking Apple system paths (`com.apple.iTunesCloud`, `com.apple.internal.ck`, `com.apple.appleaccountd`)
- **Binary naming:** Executables named after legitimate macOS processes (`SystemUpdate`, `iSync`, `loginwindow`)
- **Gatekeeper bypass:** Quarantine attribute removal via `xattr -rd com.apple.quarantine`
- **Certificate pinning:** Custom TLS certificate prevents traffic inspection
- **Stripped binaries:** Later ROOFDECK variant stripped of debug symbols
- **LaunchAgent masquerade:** Persistence plists use Apple-like naming with `--type=renderer` parameter
- **Lock file anti-concurrency:** `$TMPDIR/tmp*.lock` prevents multiple instances and complicates analysis

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - Domains: `[.]` replacing dots (e.g., `technicais.sytes[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `176.97.114[.]232`)
> - URLs: `hxxps://` prefix

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Terraform provider (fake registry) | Unknown | Malicious provider served from `registry.hashicorp-aws[.]com` |
| Terraform provider (fake registry) | Unknown | Malicious provider served from `registry.hashicorp-aws[.]io` |
| Terraform provider (fake registry) | Unknown | Malicious provider served from `registry.hashicorp-terraform[.]io` |
| `gocommunity-io/dockerd` (related) | 222 downloads | Malicious Terraform provider on legitimate registry |
| `kreuzwenker/docker` (related) | 1,449 downloads | Malicious Terraform provider on legitimate registry |

### File System

| Platform | Path | Hash (SHA-1) | Description |
|----------|------|--------------|-------------|
| macOS | `~/Library/com.apple.iTunesCloud/SystemUpdate` | `02df07a173ab03b82a4fb6a08973fff8b1467f28` | FLATROOF backdoor binary |
| macOS | `~/Library/com.apple.internal.ck/iSync` | `c491d477dbe0ae04e9aed9dbe237144c03f73ec4` | ROOFDECK backdoor binary |
| macOS | `~/Library/com.apple.appleaccountd/loginwindow` | `5728b11d30586bbfc1d8bd12df1c722a06e767a2` | ROOFDECK (stripped variant) |
| macOS | `$HOME/.config/.repl_history` | N/A | ROOFDECK configuration file |
| macOS | `/private/tmp/.pipe-airway` | N/A | ROOFDECK IPC named pipe |
| macOS | `$TMPDIR/tmp*.lock` | N/A | FLATROOF lock file |
| macOS | `~/Library/LaunchAgents/com.apple.*.plist` | N/A | Persistence LaunchAgent plists |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `technicais.sytes[.]net` | FLATROOF C2 |
| Domain | `storage.hubpage[.]cloud` | ROOFDECK C2 (initial) |
| Domain | `grenight[.]com` | ROOFDECK C2 (post-April 20) |
| Domain | `registry.hashicorp-aws[.]com` | Fake Terraform registry |
| Domain | `registry.hashicorp-aws[.]io` | Fake Terraform registry |
| Domain | `registry.hashicorp-terraform[.]io` | Fake Terraform registry |
| IP | `176.97.114[.]232` | FLATROOF C2 server |
| IP | `45.11.59[.]140` | ROOFDECK C2 server |
| IP | `85.137.56[.]245` | ROOFDECK rotated C2 server |
| IP | `85.137.56[.]10` | ROOFDECK staging server |
| Domain | `anesthesiaschool[.]com` | Associated infrastructure (certificate "ub" user) |
| Domain | `app.heyhay[.]online` | Associated infrastructure |
| Domain | `dela.servehttp[.]com` | Associated infrastructure |
| Domain | `galaxy-royal[.]online` | Associated infrastructure |
| Domain | `heyhay[.]online` | Associated infrastructure |
| Domain | `mactroubleshoots[.]pro` | Associated infrastructure |
| Domain | `tinklify[.]com` | Associated infrastructure |
| Domain | `vaimage[.]com` | Associated infrastructure |
| Domain | `wss.sytes[.]net` | Associated infrastructure |
| URL Pattern | `hxxps://[C2]/app_version` | ROOFDECK C2 beacon endpoint |
| Cert SHA-256 | `4b2d3e8ccce8920a6d01e7d02b84236545a20e5f754b3eec253f8b416b731daa` | ROOFDECK pinned TLS certificate |
| Cert SHA-1 | `4ad92bf92ee614b05c340ce17bef7b6ef5a25e82` | ROOFDECK pinned TLS certificate |
| Cert Serial | `1cd6d13ff15adbf7a42025d10ec99b4a` | ROOFDECK pinned TLS certificate |

### Behavioral

- Terraform `init` resolving providers from non-standard registries containing "hashicorp" in the domain name
- Creation of executable files under `~/Library/com.apple.*` directories that are not genuine Apple paths
- LaunchAgent plists with `--type=renderer` command-line parameter
- Outbound connections to Nostr relay infrastructure from non-Nostr applications
- Process named `SystemUpdate`, `iSync`, or `loginwindow` running from user Library directories
- Named pipe creation at `/private/tmp/.pipe-airway`
- Python-based data harvesting targeting browser data, command histories, and keychains

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1566.003 | Phishing: Spearphishing via Service | Fake job interview lures via GitHub repositories with coding challenges |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Weaponized `.terraform.lock.hcl` files directing Terraform to malicious provider registries |
| T1204.002 | User Execution: Malicious File | Victim runs `terraform init` which fetches and executes malicious provider |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Backdoors placed in Apple-like paths (`com.apple.*`) with system process names (`SystemUpdate`, `loginwindow`) |
| T1543.001 | Create or Modify System Process: Launch Agent | Persistence via LaunchAgent plists in `~/Library/LaunchAgents/` |
| T1553.001 | Subvert Trust Controls: Gatekeeper Bypass | `xattr -rd com.apple.quarantine` removes Gatekeeper quarantine attributes |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS-based C2 communication to `/app_version` endpoint |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | RSA-2048 signed C2 commands with pinned TLS certificates |
| T1102.001 | Web Service: Dead Drop Resolver | Nostr relay network used for C2 operator discovery |
| T1005 | Data from Local System | Python module harvests browser data, command histories, keychains, credentials |
| T1059.006 | Command and Scripting Interpreter: Python | Python-based data harvesting module for credential and browser data exfiltration |
| T1027 | Obfuscated Files or Information | Stripped binary variant of ROOFDECK to hinder static analysis |

<!-- revision: P0 #2 — changed T1027.002 (Software Packing) to T1027 (parent). Stripping debug symbols is obfuscation, not packing (packing involves runtime compression/encryption with an unpacker stub). -->

## Impact Assessment

**Breadth:** Targeted attack against specific individual at an IT services company; however, the Terraform provider supply chain vector has broad implications for any organization using custom or third-party Terraform providers. The fake registries could be reused against multiple targets.

**Depth:** Full system compromise with persistent backdoor access, credential harvesting, and data exfiltration. The ROOFDECK backdoor's RSA-2048 command signing and Nostr relay C2 indicate high operational security by the threat actor.

**Stealth:** High. The backdoors masquerade as Apple system components in plausible (but non-genuine) Apple directory paths. The Terraform lock file vector exploits developer trust in infrastructure-as-code workflows. Nostr relay C2 blends with legitimate decentralized social media traffic.

**Significance:** This campaign marks the first documented use of Terraform registries as a malware distribution vector and demonstrates TraderTraitor expanding beyond cryptocurrency-sector targets to general IT services firms.

## Detection & Remediation

### Immediate Detection

```bash
# Check for FLATROOF/ROOFDECK file paths
ls -la ~/Library/com.apple.iTunesCloud/SystemUpdate 2>/dev/null
ls -la ~/Library/com.apple.internal.ck/iSync 2>/dev/null
ls -la ~/Library/com.apple.appleaccountd/loginwindow 2>/dev/null
ls -la /private/tmp/.pipe-airway 2>/dev/null
ls -la ~/.config/.repl_history 2>/dev/null

# Check for suspicious LaunchAgents with --type=renderer
grep -rl "renderer" ~/Library/LaunchAgents/ 2>/dev/null

# Check for known malicious hashes (SHA-1)
find ~/Library -type f -exec shasum {} \; 2>/dev/null | grep -E "02df07a173ab03b82a4fb6a08973fff8b1467f28|c491d477dbe0ae04e9aed9dbe237144c03f73ec4|5728b11d30586bbfc1d8bd12df1c722a06e767a2"

# Audit Terraform lock files for malicious registries
grep -rn "hashicorp-aws\.\|hashicorp-terraform\." .terraform.lock.hcl */.terraform.lock.hcl 2>/dev/null

# Check DNS resolution logs for C2 domains
log show --predicate 'process == "mDNSResponder"' --last 30d | grep -E "technicais\.sytes\.net|hubpage\.cloud|grenight\.com"
```

### Remediation

1. **Containment:** Immediately isolate any macOS system with confirmed FLATROOF/ROOFDECK artifacts. Block C2 domains and IPs at perimeter firewalls.
2. **Eradication:** Remove malicious binaries, LaunchAgent plists, configuration files (`.repl_history`), and named pipes (`.pipe-airway`). Verify no additional persistence mechanisms exist.
3. **Credential Rotation:** Rotate all credentials, tokens, API keys, and SSH keys that were accessible from compromised systems. The Python data harvesting module targets browser data, keychains, and command histories.
4. **Terraform Audit:** Audit all `.terraform.lock.hcl` files across repositories for references to non-standard registries. Enforce registry allowlists in Terraform configurations.
5. **Supply Chain Review:** Review any GitHub repositories cloned as part of interview or assessment processes. Verify Terraform provider sources.

### Long-Term Hardening

- **Terraform Registry Allowlisting:** Configure network-level controls to permit Terraform provider downloads only from `registry.terraform.io` and approved private registries.
- **Lock File Review:** Treat `.terraform.lock.hcl` changes with the same scrutiny as dependency lock file changes in other ecosystems. Add CI checks that flag non-standard registry URLs.
- **macOS Endpoint Monitoring:** Deploy EDR with visibility into LaunchAgent creation, `xattr` quarantine removal, and process execution from user Library directories.
- **Social Engineering Awareness:** Train engineering staff on fake job interview lures targeting developers, particularly those involving code repositories or infrastructure-as-code exercises.
- **Nostr Traffic Monitoring:** Alert on outbound connections to known Nostr relay infrastructure from systems not expected to use decentralized social protocols.

## Detection Rules

These rules target the specific IOCs and behavioral patterns of the TraderTraitor FLATROOF/ROOFDECK campaign. The Sigma rule covers macOS backdoor file drops; Suricata and Snort rules cover DNS, TLS, and HTTP C2 indicators; YARA rules cover binary-level and Terraform lock file signatures. Compiles do not equal fires -- verify in your pipeline.

<!-- revision: P0 #1 — CUT Sigma Rule 1 (Terraform Init Against Malicious HashiCorp-Impersonating Registry, id 8a3f1d2e-5b7c-4e9a-b1d3-6f8e2a4c7b90). Reason: fundamentally broken detection logic. The three attacker registry domains (registry.hashicorp-aws.com, registry.hashicorp-aws.io, registry.hashicorp-terraform.io) are read from .terraform.lock.hcl and .tf configuration files at runtime; they NEVER appear in the terraform process command line. The CommandLine|contains selection would never fire. The DNS rules (Suricata SIDs 2026092803/2026092804, Snort SIDs 2026092811-2026092813) and YARA rule TraderTraitor_Terraform_LockFile_Poisoned already cover this vector via network and file-level detection respectively. -->

<!-- revision: P1 #3 — CUT Sigma Rule 3 (macOS Gatekeeper Bypass via xattr Quarantine Removal, id 9e2b5c7d-1a4f-48e3-b6d9-3c8a5e7f1d40). Reason: purely generic TTP detection — fires on ANY xattr -rd com.apple.quarantine invocation with zero campaign-specific context. Wrong altitude for a specific/strict report. Sigma Rule 2 (file drop detection) already catches the actual FLATROOF/ROOFDECK payloads at their distinctive paths. -->

### Sigma: FLATROOF/ROOFDECK Backdoor File Drop in Apple-Masquerade Directories

Detects file creation at the specific paths used by FLATROOF and ROOFDECK backdoor variants, including the IPC pipe and configuration file locations.

**Status:** compile ✅ compiles · confidence: high

<!-- audit: sigma check failed due to MITRE ATT&CK data endpoint proxy block (HTTP 403) — not a rule defect. sigma convert --without-pipeline to splunk: exit 0, output: TargetFilename IN ("*/Library/com.apple.iTunesCloud/SystemUpdate*", "*/Library/com.apple.internal.ck/iSync*", "*/Library/com.apple.appleaccountd/loginwindow*", "*/.config/.repl_history", "*/private/tmp/.pipe-airway*"). sigma convert --without-pipeline to log_scale: exit 0. Tag revision: removed attack.persistence and attack.t1543.001 (rule detects binary file drops, not LaunchAgent plist creation) and tactic-only tags per spec; retained attack.t1036.005 (Masquerading). FP risk: none expected — these specific path+filename combinations are unique to this malware family. Requires file event logging on macOS endpoints (e.g., via EDR or Sysmon for macOS). -->

```yaml
title: FLATROOF/ROOFDECK Backdoor File Drop in Apple-Masquerade Directories
id: 7c4e9a1b-3d8f-42e6-a5c7-1b9d3e6f8a2c
status: experimental
description: >
    Detects creation of executable files in directories that masquerade as
    Apple system directories under ~/Library, matching paths used by FLATROOF
    (SystemUpdate) and ROOFDECK (iSync, loginwindow) backdoors deployed by
    TraderTraitor actors.
references:
    - https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/
author: Actioner
date: 2026-09-28
tags:
    - attack.t1036.005
logsource:
    category: file_event
    product: macos
detection:
    selection_flatroof:
        TargetFilename|contains: '/Library/com.apple.iTunesCloud/SystemUpdate'
    selection_roofdeck_isync:
        TargetFilename|contains: '/Library/com.apple.internal.ck/iSync'
    selection_roofdeck_loginwindow:
        TargetFilename|contains: '/Library/com.apple.appleaccountd/loginwindow'
    selection_config:
        TargetFilename|endswith: '/.config/.repl_history'
    selection_pipe:
        TargetFilename|contains: '/private/tmp/.pipe-airway'
    condition: selection_flatroof or selection_roofdeck_isync or selection_roofdeck_loginwindow or selection_config or selection_pipe
falsepositives:
    - None expected; these specific path combinations are unique to this malware
level: critical
```

### Snort: TraderTraitor C2 DNS and HTTP Detection

Seven rules for Snort 2.9: DNS lookups for the three primary C2 domains (UDP and TCP variants) and the ROOFDECK `/app_version` HTTP beacon URI (informational -- correlate with DNS IOCs before acting).

**Status:** compile ✅ compiles · confidence: high

<!-- audit: Snort 2.9.20 validated successfully: "Snort successfully validated the configuration!" All 7 SIDs (2026092811-2026092817) loaded. DNS rules use wire-format content matching (length-prefixed labels) for both UDP (SIDs 2026092811-2026092813) and TCP (SIDs 2026092815-2026092817). SID 2026092814 matches /app_version in http_uri — demoted to classtype:bad-unknown / informational per critic (common health-check endpoint, high FP in isolation; anchor on DNS IOC hits first). TCP DNS variants added per P3 recommendation; wire-format label matching works identically in TCP DNS payloads (2-byte length prefix does not interfere with substring content match). -->

```
alert udp $HOME_NET any -> any 53 (msg:"TRADERTRAITOR FLATROOF C2 DNS Lookup - technicais.sytes.net"; content:"|0a|technicais|05|sytes|03|net"; nocase; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; classtype:trojan-activity; sid:2026092811; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"TRADERTRAITOR ROOFDECK C2 DNS Lookup - storage.hubpage.cloud"; content:"|07|storage|07|hubpage|05|cloud"; nocase; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; classtype:trojan-activity; sid:2026092812; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"TRADERTRAITOR ROOFDECK C2 DNS Lookup - grenight.com"; content:"|08|grenight|03|com"; nocase; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; classtype:trojan-activity; sid:2026092813; rev:1;)

alert tcp $HOME_NET any -> any $HTTP_PORTS (msg:"TRADERTRAITOR ROOFDECK C2 Beacon URI - /app_version [Informational]"; content:"/app_version"; http_uri; classtype:bad-unknown; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; sid:2026092814; rev:2;)

alert tcp $HOME_NET any -> any 53 (msg:"TRADERTRAITOR FLATROOF C2 DNS Lookup - technicais.sytes.net [TCP]"; content:"|0a|technicais|05|sytes|03|net"; nocase; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; classtype:trojan-activity; sid:2026092815; rev:1;)

alert tcp $HOME_NET any -> any 53 (msg:"TRADERTRAITOR ROOFDECK C2 DNS Lookup - storage.hubpage.cloud [TCP]"; content:"|07|storage|07|hubpage|05|cloud"; nocase; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; classtype:trojan-activity; sid:2026092816; rev:1;)

alert tcp $HOME_NET any -> any 53 (msg:"TRADERTRAITOR ROOFDECK C2 DNS Lookup - grenight.com [TCP]"; content:"|08|grenight|03|com"; nocase; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; classtype:trojan-activity; sid:2026092817; rev:1;)
```

### Suricata: TraderTraitor FLATROOF/ROOFDECK C2 Communication

Six rules covering DNS lookups for all three C2 domains, DNS queries containing the Terraform registry impersonation pattern, TLS SNI matching for `hubpage[.]cloud`, and the ROOFDECK HTTP beacon URI `/app_version` (informational -- correlate with DNS IOCs before acting).

**Status:** compile ✅ compiles · confidence: high

<!-- audit: suricata -T -S validated successfully: "Configuration provided was successfully loaded. Exiting." All 6 SIDs (2026092801-2026092806) loaded. Rules use Suricata-native dot-notation sticky buffers (dns.query, tls.sni, http.uri). SID 2026092804 matches "hashicorp-aws" substring in DNS to catch both .com and .io registry variants. SID 2026092806 (/app_version URI): demoted to classtype:bad-unknown per critic — common health-check/API endpoint, high FP potential in isolation; msg tagged [Informational] to flag as correlation-only. Nostr relay domains intentionally excluded from network rules as they are legitimate public infrastructure. -->

```
alert dns $HOME_NET any -> any any (msg:"TRADERTRAITOR FLATROOF C2 DNS Lookup - technicais.sytes.net"; dns.query; content:"technicais.sytes.net"; nocase; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; classtype:trojan-activity; sid:2026092801; rev:1;)

alert dns $HOME_NET any -> any any (msg:"TRADERTRAITOR ROOFDECK C2 DNS Lookup - storage.hubpage.cloud"; dns.query; content:"storage.hubpage.cloud"; nocase; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; classtype:trojan-activity; sid:2026092802; rev:1;)

alert dns $HOME_NET any -> any any (msg:"TRADERTRAITOR ROOFDECK C2 DNS Lookup - grenight.com"; dns.query; content:"grenight.com"; nocase; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; classtype:trojan-activity; sid:2026092803; rev:1;)

alert dns $HOME_NET any -> any any (msg:"TRADERTRAITOR Malicious Terraform Registry DNS Lookup"; dns.query; content:"hashicorp-aws"; nocase; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; classtype:trojan-activity; sid:2026092804; rev:1;)

alert tls $HOME_NET any -> any any (msg:"TRADERTRAITOR ROOFDECK C2 TLS SNI - hubpage.cloud"; tls.sni; content:"hubpage.cloud"; nocase; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; classtype:trojan-activity; sid:2026092805; rev:1;)

alert http $HOME_NET any -> any any (msg:"TRADERTRAITOR ROOFDECK C2 Beacon URI Pattern - /app_version [Informational]"; http.uri; content:"/app_version"; classtype:bad-unknown; reference:url,www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/; sid:2026092806; rev:2;)
```

### YARA: FLATROOF/ROOFDECK Backdoor and Poisoned Terraform Lock File Detection

Three YARA rules: (1) FLATROOF_macOS_Backdoor matches ARM64 Mach-O Rust binaries containing FLATROOF-specific strings; (2) ROOFDECK_macOS_Backdoor matches Rust binaries with Nostr relay strings or ROOFDECK-specific paths and C2 indicators; (3) TraderTraitor_Terraform_LockFile_Poisoned matches Terraform-context files (filesize < 1MB, requires `provider` or `h1:` alongside the malicious registry domains).

**Status:** compile ✅ compiles · confidence: high

<!-- audit: yarac compiled with exit 0, no errors or warnings. FLATROOF rule: Mach-O header (CFFA EDFE at offset 0) + rustc + 3 of 5 specific strings including C2 domain and file paths. ROOFDECK rule: Mach-O header + rustc + either 2 of 4 Nostr relay strings OR 3 of 7 ROOFDECK-specific strings. Both rules are deliberately strict to minimize FPs. FAT/Universal Mach-O limitation documented in macho_caveat metadata field (P3 #8). Terraform lock file rule: revised per P1 #5 — added filesize < 1MB constraint and requires Terraform-contextual string ("provider" or "h1:") alongside the registry domains; prevents matching threat reports, PDFs, emails that mention these domains. SHA-1 hashes are in metadata only (source did not provide SHA-256). -->

```yara
rule FLATROOF_macOS_Backdoor
{
    meta:
        description = "Detects FLATROOF (macOS.Gaslight) ARM64 Rust-based backdoor deployed by TraderTraitor DPRK actors"
        author = "Actioner"
        date = "2026-09-28"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        hash_sha1 = "02df07a173ab03b82a4fb6a08973fff8b1467f28"
        threat_actor = "TraderTraitor"
        malware_family = "FLATROOF"
        macho_caveat = "Mach-O magic at offset 0 matches thin binaries only; FAT/Universal (0xCAFEBABE/0xBEBAFECA) require FAT header parsing to reach embedded slices"

    strings:
        $mach_header = { CF FA ED FE }
        $s1 = "SystemUpdate" ascii
        $s2 = "technicais.sytes.net" ascii
        $s3 = "tmp.lock" ascii
        $s4 = "com.apple.iTunesCloud" ascii
        $rust1 = "rustc" ascii
        $pipe = ".pipe-airway" ascii

    condition:
        $mach_header at 0 and
        $rust1 and
        3 of ($s1, $s2, $s3, $s4, $pipe)
}

rule ROOFDECK_macOS_Backdoor
{
    meta:
        description = "Detects ROOFDECK ARM64 Rust-based backdoor with Nostr relay C2, deployed by TraderTraitor DPRK actors"
        author = "Actioner"
        date = "2026-09-28"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        hash_sha1_isync = "c491d477dbe0ae04e9aed9dbe237144c03f73ec4"
        hash_sha1_loginwindow = "5728b11d30586bbfc1d8bd12df1c722a06e767a2"
        threat_actor = "TraderTraitor"
        malware_family = "ROOFDECK"
        macho_caveat = "Mach-O magic at offset 0 matches thin binaries only; FAT/Universal (0xCAFEBABE/0xBEBAFECA) require FAT header parsing to reach embedded slices"

    strings:
        $mach_header = { CF FA ED FE }
        $s1 = "app_version" ascii
        $s2 = "hubpage.cloud" ascii
        $s3 = "grenight.com" ascii
        $s4 = ".repl_history" ascii
        $s5 = "com.apple.internal.ck" ascii
        $s6 = "com.apple.appleaccountd" ascii
        $nostr1 = "relay.damus.io" ascii
        $nostr2 = "nos.lol" ascii
        $nostr3 = "nostr.mom" ascii
        $nostr4 = "relay.snort.social" ascii
        $rust1 = "rustc" ascii
        $pipe = ".pipe-airway" ascii

    condition:
        $mach_header at 0 and
        $rust1 and
        (
            2 of ($nostr1, $nostr2, $nostr3, $nostr4) or
            3 of ($s1, $s2, $s3, $s4, $s5, $s6, $pipe)
        )
}

rule TraderTraitor_Terraform_LockFile_Poisoned
{
    meta:
        description = "Detects weaponized Terraform lock files referencing malicious HashiCorp-impersonating registries used by TraderTraitor"
        author = "Actioner"
        date = "2026-09-28"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        threat_actor = "TraderTraitor"

    strings:
        $reg1 = "registry.hashicorp-aws.com" ascii nocase
        $reg2 = "registry.hashicorp-aws.io" ascii nocase
        $reg3 = "registry.hashicorp-terraform.io" ascii nocase
        $tf_ctx1 = "provider" ascii
        $tf_ctx2 = "h1:" ascii

    condition:
        filesize < 1MB and
        any of ($reg*) and
        any of ($tf_ctx*)
}
```

## Lessons Learned

1. **Terraform is now a supply-chain attack surface.** This campaign demonstrates that `.terraform.lock.hcl` files can be weaponized to redirect provider downloads to attacker infrastructure. Organizations should treat Terraform lock file changes with the same rigor as `package-lock.json` or `go.sum` modifications, and enforce registry allowlists.

2. **DPRK targeting has expanded beyond crypto.** TraderTraitor's pivot to a non-cryptocurrency IT services firm indicates that any organization with valuable infrastructure access or intellectual property is a potential target. The fake job interview lure remains highly effective against engineers.

3. **Nostr as C2 infrastructure.** The use of Nostr relays for operator discovery introduces a novel and resilient C2 channel that blends with legitimate decentralized social media traffic, complicating network-based detection. Defenders need visibility into WebSocket connections to relay infrastructure from unexpected processes.

4. **macOS remains under-monitored.** The attack exploits the common gap in macOS endpoint visibility, particularly around file creation in user Library directories, LaunchAgent persistence, and quarantine attribute manipulation. Organizations with macOS developer workstations need equivalent detection coverage to their Windows and Linux fleets.

## Sources

- [SentinelOne Labs - "Don't Call Us, We'll Call Your APIs"](https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/) -- Primary technical analysis of FLATROOF/ROOFDECK backdoors, IOCs, C2 infrastructure, and Terraform supply chain vector
- [The Hacker News - "Attackers Use Malicious Terraform Providers"](https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html) -- Coverage of first documented Terraform registry malware distribution, broader context on related DPRK supply chain campaigns

---
*Report generated by Actioner*
