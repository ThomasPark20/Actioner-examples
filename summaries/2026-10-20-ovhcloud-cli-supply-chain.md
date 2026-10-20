# OVHcloud CLI Supply Chain Attack (GlassWorm)

**Date:** 2026-10-20  
**Status:** FINAL  
**Altitude:** Specific (PoC/advisory-specific)  
**Leniency:** Strict

---

## Executive Summary

On 19 October 2026, an attacker using a hijacked GitHub contributor account (`HassenBF`) replaced the release archives for five versions (v0.11.0 through v0.15.0) of the OVHcloud CLI tool on GitHub. The replacement binaries were live for up to 94 minutes before OVHcloud deleted them. The malicious binaries were compiled from a dirty working tree with distinct build metadata and lacked the GoReleaser provenance of legitimate builds. A related JavaScript loader (`preinstall.js`) associated with the GlassWorm campaign uses Unicode variation-selector obfuscation and a Solana blockchain dead-drop resolver for C2 staging. The attack targeted cloud credentials, SSH keys, and API secrets stored on developer machines. OVHcloud published a clean, immutable v0.16.0 release the same day.

---

## Background

The OVHcloud CLI (`ovhcloud-cli`) is a Go-based command-line tool for managing OVHcloud infrastructure. It is distributed via GitHub Releases, Homebrew, Docker, and `go install`. The attack exclusively targeted the GitHub Release asset distribution channel. Homebrew, Docker, and source-based installations were not affected because the `v0.15.0` Git tag was never modified (it still points to commit `760fd72d`).

The attacker is linked to the **GlassWorm** threat group, which has been tracked since at least October 2025. GlassWorm is known for using invisible Unicode characters (variation selectors) to encode payloads and Solana blockchain memos as dead-drop resolvers to dynamically fetch C2 URLs.

---

## Attack Timeline

| Time (UTC) | Event |
|---|---|
| **2026-03-05 to 03-06** | Four personal repositories of the `HassenBF` GitHub account were force-pushed with a GlassWorm loader |
| **2026-10-13 08:35:05** | Timestamp embedded in the malicious binary's pseudo-version (`vcs.time`) |
| **2026-10-19 12:47** | First malicious release assets uploaded (v0.15.0: Linux arm64, Linux x86_64, Darwin arm64, Darwin x86_64, Windows x86_64, and checksums.txt) |
| **2026-10-19 12:57** | v0.15.0 asset replacement complete |
| **2026-10-19 13:01** | v0.14.0 Linux arm64 asset replaced |
| **2026-10-19 13:04** | v0.14.0 checksums.txt replaced |
| **2026-10-19 13:08** | v0.13.0 Linux arm64 asset replaced |
| **2026-10-19 13:11** | v0.13.0 checksums.txt replaced |
| **2026-10-19 ~13:12** | Last known asset replacement (v0.11.0 and v0.12.0 times not precisely documented) |
| **2026-10-19 13:50** | Customer CI job fails on pinned SHA-256 hash; files GitHub issue [#300](https://github.com/ovh/ovhcloud-cli/issues/300) |
| **2026-10-19 14:21** | OVHcloud deletes all malicious release assets (94-minute window) |
| **2026-10-19 16:00** | Clean v0.16.0 Git tag pushed |
| **2026-10-19 17:16** | v0.16.0 published as an **immutable release** by the `ovh-cds` service account |

---

## Root Cause

The attacker compromised the GitHub account `HassenBF` (user ID 4911006), a contributor who had previously submitted work to OVHcloud documentation repositories. The account was not a public organization member. Access to the account provided the ability to upload replacement release assets to existing releases for the `ovh/ovhcloud-cli` repository, likely via a personal access token or session with write permissions to the release assets.

**Contributing factors:**
- The OVHcloud CLI install script (`install.sh`) did not verify SHA-256 hashes of downloaded archives
- The CLI's built-in `upgrade` command (in `internal/upgrade/install.go`) downloaded archives from GitHub release URLs without hash verification
- GitHub Releases did not have immutable release protection enabled until v0.16.0
- No build attestation or provenance signing was in place for releases prior to v0.16.0

---

## Technical Analysis

### Stage 1: Release Asset Replacement

The attacker built replacement binaries using a standard `go build -ldflags="-s -w"` command rather than the project's GoReleaser configuration. This produced binaries with distinct build metadata:

- **Module version:** `v0.15.1-0.20261013083505-5ead8ef9b43d+dirty` (pseudo-version with `+dirty` suffix)
- **VCS revision:** `5ead8ef9b43d354dfb5caadff803b11afc8c5c58`
- **VCS modified:** `true` (uncommitted changes present)
- **Missing ldflag:** `-X github.com/ovh/ovhcloud-cli/internal/version.Version={{.Tag}}` (present in legitimate GoReleaser builds)
- **Missing flag:** `-trimpath` (used in legitimate builds to strip VCS metadata)

Running `go version -m` on the malicious binary reveals these tell-tale differences from a legitimate GoReleaser-produced binary.

**Affected platforms:** macOS (x86_64, arm64), Linux (x86_64, arm64), Windows (x86_64), and `checksums.txt` files.  
**Not affected:** Linux i386, Windows i386, Windows arm64, WebAssembly builds.

### Stage 2: GlassWorm Loader (preinstall.js)

The associated GlassWorm loader (linked to the same hijacked account's repositories) uses the following technique chain:

1. **Obfuscation:** Payload encoded using invisible Unicode variation-selector characters (U+FE00 to U+FE0F and U+E0100 to U+E01EF). The file appears empty/blank visually.
2. **Decryption:** AES-256-CBC with hardcoded key and IV:
   - Key: `zetqHyfDfod88zloncfnOaS9gGs90ONX`
   - IV: `a041fdaa0521fb5c3e26b217aaf24115`
3. **Stage two:** 4,407 bytes after decryption, executed inside a Node.js `vm` context with `require` exposed.

### Stage 3: Dead-Drop Resolution via Solana

The decrypted stage-two payload:
1. Queries public Solana RPC endpoints for recent transaction signatures of a specific wallet
2. Reads the memo field of the most recent transaction, which contains JSON with a base64-encoded `link` field
3. Fetches the payload from the decoded URL
4. The HTTP response includes `ivbase64` and `secretkey` headers used to decrypt the response body
5. Decrypted body is passed to `eval()`

### Evasion Techniques

- **Locale check:** Exits if the system appears to have Russian locale/timezone settings
- **Time delay:** Waits 10 seconds before performing the locale check
- **Throttle file:** Writes `~/init.json` on macOS to limit re-execution to approximately once every two days
- **Dynamic C2:** The Solana dead-drop resolver allows the operator to change the payload URL without modifying any repository code

### Targeted Credentials

The payload is believed to target (OVHcloud has not confirmed the full list):
- `~/.ovh.conf` (OVHcloud API credentials)
- `.npmrc`, `.pypirc`, `.netrc`
- SSH keys
- Kubernetes configs
- `.env` files
- Cloud provider credentials
- OVHcloud API and consumer keys

---

## IOCs

### File Hashes (SHA-256)

| File | Hash | Status |
|---|---|---|
| v0.15.0 `ovhcloud-cli_Linux_arm64.tar.gz` (malicious) | `3833daffcaaaab27e4e0e0833240ffcb1df8df648f4ec0bc4a75c176e28933cb` | Malicious |
| v0.15.0 `ovhcloud-cli_Linux_arm64.tar.gz` (clean) | `5c2beb56e6d83a4b426565a1557791ef759316abcc4effb38dd627c90aeb80e0` | Legitimate |
| GlassWorm `preinstall.js` loader | `43df42fd79f6f81e530892b54634598770d6e496796a863c596e616bcb3fec70` | Malicious |
| GlassWorm decrypted stage-two | `0f79989912572a24ba13baabb32b3fd084496271c51448d47b66fe1aedbf293c` | Malicious |

### Build Metadata (Malicious Binary Fingerprint)

```
mod  github[.]com/ovh/ovhcloud-cli v0.15.1-0.20261013083505-5ead8ef9b43d+dirty
build  vcs.revision=5ead8ef9b43d354dfb5caadff803b11afc8c5c58
build  vcs.modified=true
build  -ldflags="-s -w"
```

### Cryptographic Material

| Type | Value |
|---|---|
| AES-256-CBC Key | `zetqHyfDfod88zloncfnOaS9gGs90ONX` |
| AES-256-CBC IV | `a041fdaa0521fb5c3e26b217aaf24115` |

### Blockchain Indicators

| Type | Value |
|---|---|
| Solana wallet (dead-drop) | `BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC` |

### File Paths

| Path | Description |
|---|---|
| `~/init.json` | macOS throttle marker (GlassWorm) |
| `~/.ovh.conf` | Targeted credential file |
| `preinstall.js` | GlassWorm loader filename |

### GitHub Accounts

| Account | Role |
|---|---|
| `HassenBF` (ID 4911006) | Hijacked contributor account used to upload malicious assets |
| Affected repos: `treasure-hunt-game`, `crwn-clothing`, `next-dashboard`, `padel-bot` | Force-pushed with loader in March 2026 |

### Network Indicators

- HTTP response headers `ivbase64` and `secretkey` in stage-two payload delivery
- HTTP request header `os` sent with platform identifier during payload fetch
- Solana JSON-RPC method `getSignaturesForAddress` with the wallet above

**Note:** No C2 domains or IPs have been disclosed. The Solana dead-drop mechanism means the C2 URL is dynamic and was not captured before deletion.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Release archives replaced on GitHub |
| Valid Accounts | T1078 | Hijacked `HassenBF` GitHub account |
| Command and Scripting Interpreter: JavaScript | T1059.007 | `eval()` execution in Node.js `vm` context |
| Obfuscated Files or Information | T1027 | Unicode variation-selector encoding |
| Credentials in Files | T1552.001 | Harvesting `.ovh.conf`, `.npmrc`, `.netrc`, `.env` |
| Unsecured Credentials: Private Keys | T1552.004 | SSH key collection |
| Web Service: Dead Drop Resolver | T1102.001 | Solana blockchain memo as C2 resolver |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTP(S) payload delivery |
| System Information Discovery: System Language Discovery | T1614.001 | Russian locale check for evasion |
| System Time Discovery | T1124 | Timezone/UTC offset check |
| Virtualization/Sandbox Evasion: Time Based Evasion | T1497.003 | 10-second delay; throttle file limiting re-execution |

---

## Impact Assessment

**Severity: HIGH**

- **Exposure window:** Up to 94 minutes (12:47 to 14:21 UTC on 2026-10-19)
- **Affected versions:** v0.11.0 through v0.15.0 release archives on GitHub
- **Affected platforms:** macOS (x86_64, arm64), Linux (x86_64, arm64), Windows (x86_64)
- **Unaffected channels:** Homebrew, Docker, `go install`, source builds, Linux i386, Windows i386/arm64, WebAssembly
- **Data at risk:** OVHcloud API credentials, SSH keys, cloud provider credentials, npm/PyPI tokens, Kubernetes configs, `.env` secrets
- **Blast radius:** Any machine that downloaded and executed the CLI from GitHub Releases during the 94-minute window, or that ran `ovhcloud upgrade` pulling from the compromised assets. The broader exposure from v0.11.0-v0.14.0 depends on how many users re-download older release archives.
- **Containment:** OVHcloud deleted assets within ~91 minutes of the first community report. v0.16.0 is now the only available release and uses immutable release protection and signed tags.

---

## Detection & Remediation

### Immediate Actions

1. **Verify installed binaries:** Run `go version -m $(which ovhcloud)` and check for the malicious pseudo-version string `v0.15.1-0.20261013083505-5ead8ef9b43d`
2. **Compare SHA-256 hashes** of any cached or archived OVHcloud CLI downloads against the known-bad hash
3. **Upgrade to v0.16.0** immediately: `gh release verify-asset v0.16.0 <file>` validates against the release attestation
4. **Rotate credentials** on any machine that may have executed the compromised binary:
   - OVHcloud API keys and consumer tokens
   - SSH keys
   - npm/PyPI tokens
   - Kubernetes service account credentials
   - Any secrets in `.env` files
5. **Audit CI/CD pipelines** that download OVHcloud CLI from GitHub Releases without hash pinning

### Long-Term Hardening

- Pin SHA-256 hashes in all CI/CD download steps
- Enable GitHub release attestation verification
- Monitor for `ivbase64`/`secretkey` response headers in HTTP proxy logs
- Block or alert on Solana RPC calls from build/production infrastructure
- Implement allowlisting for outbound connections from CI runners

---

## Detection Rules

**Summary:** 9 detection rules total -- 3 Sigma, 3 YARA, 3 Suricata (see revision notes below). All rules validated: Sigma rules convert cleanly via `sigma convert --without-pipeline` to both Splunk and LogScale; YARA rules compile via `yarac`; Suricata rules pass `suricata -T` with no warnings.

**Validation note:** `sigma check` fails in this environment due to an HTTP 403 when fetching MITRE ATT&CK data (a network/proxy issue, not a rule syntax issue). All Sigma rules parse and convert correctly regardless.

**Revision notes (critic pass):**
- Dropped Sigma rule "Suspicious Node.js Preinstall Script Execution" -- fails altitude gate; purely behavioral/TTP, matches every npm package with a preinstall hook.
- Dropped Sigma rule "GlassWorm Throttle File Creation - init.json" -- fails altitude and false-positive gates; `init.json` is extraordinarily generic.
- Dropped YARA rule "GlassWorm_Variation_Selector_Obfuscation" -- fails altitude gate; technique heuristic, not artifact-specific; malware already covered by GlassWorm_Loader_AES_Key and Sigma hash rules.
- Fixed Suricata rule 12 (SID 9000003): replaced truncated wallet prefix with the full 44-character Solana address for consistency and to eliminate partial collision risk.

**Cross-platform caveat:** Sigma rules below use `product: windows` (Sysmon logsource). The OVHcloud CLI attack is cross-platform (Linux, macOS, Windows). Adapt the `product` field for cross-platform EDR or Splunk deployments as needed.

**SID range note:** Suricata SIDs 9000001-9000003 are placeholders. Assign production SIDs from your organization's allocated range before deployment.

### Sigma Rules

#### 1. OVHcloud CLI Malicious Binary - Known Hash

**Type:** Sigma | **Compile:** &#x2705; compiles (Splunk + LogScale) | **Confidence:** high

Matches the known-bad SHA-256 hash of the compromised v0.15.0 Linux arm64 archive in file-event telemetry. Only one malicious archive hash is publicly known.

```yaml
title: OVHcloud CLI Malicious Binary - Known Hash
id: 8a3c1e47-d2f0-4b91-a5c8-7e9f3d1b6a42
status: experimental
description: >
  Detects the known malicious OVHcloud CLI binary (v0.15.0 Linux arm64)
  by SHA-256 hash from the October 2026 supply chain compromise.
references:
    - https://thehackernews.com/2026/10/hackers-hijack-five-ovhcloud-cli.html
    - https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool
author: Detection Engineering
date: 2026-10-20
tags:
    - attack.initial_access
    - attack.t1195.002
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Hashes|contains:
            - '3833daffcaaaab27e4e0e0833240ffcb1df8df648f4ec0bc4a75c176e28933cb'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```

#### 2. GlassWorm Loader or Stage Two - Known Hashes

**Type:** Sigma | **Compile:** &#x2705; compiles (Splunk + LogScale) | **Confidence:** high

Matches the SHA-256 hashes of the GlassWorm `preinstall.js` loader and its decrypted stage-two payload. Requires file-hash telemetry (e.g., Sysmon Event ID 15 or EDR file events).

```yaml
title: GlassWorm Loader or Stage Two - Known Hashes
id: 9b4d2f58-e3a1-4ca2-b6d9-8f0a4e2c7b53
status: experimental
description: >
  Detects the GlassWorm preinstall.js loader or decrypted stage-two payload
  by SHA-256 hash, associated with the OVHcloud CLI supply chain attack.
references:
    - https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool
author: Detection Engineering
date: 2026-10-20
tags:
    - attack.execution
    - attack.t1059.007
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Hashes|contains:
            - '43df42fd79f6f81e530892b54634598770d6e496796a863c596e616bcb3fec70'
            - '0f79989912572a24ba13baabb32b3fd084496271c51448d47b66fe1aedbf293c'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```

#### 3. OVHcloud CLI Malicious Build Metadata in Process or File

**Type:** Sigma | **Compile:** &#x2705; compiles (Splunk + LogScale) | **Confidence:** high

Matches the specific VCS commit hash or pseudo-version string from the malicious OVHcloud CLI build in command-line telemetry (e.g., from `go version -m` forensic scans). These strings are unique to this compromise. **Note:** This is a forensic sweep detection; it does not fire on normal binary execution. It requires an investigator or automated scanner to run `go version -m` against suspect binaries and log the output.

```yaml
title: OVHcloud CLI Malicious Build Metadata in Process or File
id: ce7a5b8b-b6d4-4fd5-e9ac-bc3d7b5fae86
status: experimental
description: >
  Detects command-line or file content containing the specific pseudo-version
  and commit hash from the malicious OVHcloud CLI build.
references:
    - https://thehackernews.com/2026/10/hackers-hijack-five-ovhcloud-cli.html
    - https://github.com/ovh/ovhcloud-cli/issues/300
author: Detection Engineering
date: 2026-10-20
tags:
    - attack.initial_access
    - attack.t1195.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_pseudoversion:
        CommandLine|contains: '5ead8ef9b43d354dfb5caadff803b11afc8c5c58'
    selection_module:
        CommandLine|contains: 'v0.15.1-0.20261013083505-5ead8ef9b43d'
    condition: selection_pseudoversion or selection_module
falsepositives:
    - Unlikely - highly specific commit hash
level: critical
```

### YARA Rules

#### 4. OVHcloud CLI Malicious Binary (ELF Build Metadata)

**Type:** YARA | **Compile:** &#x2705; compiles (yarac 4.5.0) | **Confidence:** high

Matches ELF binaries containing the specific build metadata from the malicious OVHcloud CLI build, including the pseudo-version, VCS commit, module path, and dirty flag. **Note:** This rule checks for the ELF magic bytes (`0x7f454c46`) and therefore matches only Linux binaries. PE (Windows) and Mach-O (macOS) variants of the malicious binary are not matched; the hash-based Sigma rules (1 and 2) partially fill this gap across all platforms.

```yara
rule OVHcloud_CLI_Malicious_Binary {
    meta:
        description = "Detects the malicious OVHcloud CLI binary from the October 2026 supply chain compromise based on build metadata strings"
        author = "Detection Engineering"
        date = "2026-10-20"
        reference = "https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool"
        hash = "3833daffcaaaab27e4e0e0833240ffcb1df8df648f4ec0bc4a75c176e28933cb"
    strings:
        $pseudo_version = "v0.15.1-0.20261013083505-5ead8ef9b43d" ascii
        $vcs_rev = "5ead8ef9b43d354dfb5caadff803b11afc8c5c58" ascii
        $module = "github.com/ovh/ovhcloud-cli" ascii
        $dirty = "+dirty" ascii
    condition:
        uint32(0) == 0x464c457f and $module and $vcs_rev and $dirty and $pseudo_version
}
```

#### 5. GlassWorm Loader AES Key

**Type:** YARA | **Compile:** &#x2705; compiles (yarac 4.5.0) | **Confidence:** high

Matches files containing the hardcoded AES-256-CBC key used by the GlassWorm `preinstall.js` loader. The key is a unique 32-byte string specific to this campaign.

```yara
rule GlassWorm_Loader_AES_Key {
    meta:
        description = "Detects GlassWorm preinstall.js loader by AES-256-CBC key and IV"
        author = "Detection Engineering"
        date = "2026-10-20"
        reference = "https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool"
        hash = "43df42fd79f6f81e530892b54634598770d6e496796a863c596e616bcb3fec70"
    strings:
        $aes_key = "zetqHyfDfod88zloncfnOaS9gGs90ONX" ascii wide
        $aes_iv = "a041fdaa0521fb5c3e26b217aaf24115" ascii wide
        $eval = "eval" ascii wide
    condition:
        filesize < 500KB and $aes_key and ($aes_iv or $eval)
}
```

#### 6. GlassWorm Solana Dead-Drop Wallet

**Type:** YARA | **Compile:** &#x2705; compiles (yarac 4.5.0) | **Confidence:** high

Matches files containing the specific Solana wallet address used as a dead-drop resolver by GlassWorm. This is a campaign-specific indicator.

```yara
rule GlassWorm_Solana_DeadDrop {
    meta:
        description = "Detects the Solana wallet address used as a dead-drop resolver by GlassWorm"
        author = "Detection Engineering"
        date = "2026-10-20"
        reference = "https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool"
    strings:
        $wallet = "BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC" ascii wide
    condition:
        $wallet
}
```

### Suricata Rules

#### 7. GlassWorm Stage-Two Response Headers

**Type:** Suricata | **Compile:** &#x2705; compiles (Suricata 7.0.3) | **Confidence:** medium

Alerts on HTTP responses containing both `ivbase64` and `secretkey` headers, used by GlassWorm to deliver decryption parameters for the stage-two payload. Caveat: custom HTTP headers are not inherently malicious, but this specific pair in server responses is distinctive of GlassWorm C2 delivery.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE GlassWorm Stage-Two Response Headers (ivbase64/secretkey)"; flow:established,to_client; http.header; content:"ivbase64"; nocase; content:"secretkey"; nocase; classtype:trojan-activity; sid:9000001; rev:1;)
```

#### 8. GlassWorm Solana Dead-Drop Wallet Lookup

**Type:** Suricata | **Compile:** &#x2705; compiles (Suricata 7.0.3) | **Confidence:** high

Alerts on HTTP request bodies containing the GlassWorm Solana wallet address, indicating a dead-drop resolver query.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE GlassWorm Solana Dead-Drop Wallet Lookup"; flow:established,to_server; http.request_body; content:"BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC"; classtype:trojan-activity; sid:9000002; rev:1;)
```

#### 9. GlassWorm Solana RPC getSignaturesForAddress

**Type:** Suricata | **Compile:** &#x2705; compiles (Suricata 7.0.3) | **Confidence:** medium

Alerts on Solana JSON-RPC `getSignaturesForAddress` calls containing the GlassWorm wallet address. This rule uses the full 44-character Solana address for consistency with rule 8 and to eliminate partial collision risk.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE GlassWorm Solana RPC getSignaturesForAddress"; flow:established,to_server; http.request_body; content:"getSignaturesForAddress"; content:"BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC"; classtype:trojan-activity; sid:9000003; rev:1;)
```

---

## Sources

- [The Hacker News: Hackers Hijack Five OVHcloud CLI Releases](https://thehackernews.com/2026/10/hackers-hijack-five-ovhcloud-cli.html)
- [OpenSourceMalware: GlassWorm Hacks OVH Cloud's CLI Tool](https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool)
- [GitHub Issue #300: ovh/ovhcloud-cli](https://github.com/ovh/ovhcloud-cli/issues/300)
- [OVHcloud CLI v0.16.0 Release](https://github.com/ovh/ovhcloud-cli/releases/tag/v0.16.0)
- [OVHcloud CLI Install Script (v0.15.0)](https://github.com/ovh/ovhcloud-cli/blob/v0.15.0/install.sh)
- [OVHcloud CLI Upgrade Code (v0.15.0)](https://github.com/ovh/ovhcloud-cli/blob/v0.15.0/internal/upgrade/install.go)
- [OVHcloud Homebrew Tap Commit](https://github.com/ovh/homebrew-tap/commit/b70a654)
- [GitHub Immutable Releases Documentation](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
