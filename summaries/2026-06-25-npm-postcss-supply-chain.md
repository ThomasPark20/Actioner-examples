# DRAFT: Malicious npm PostCSS Packages — Supply Chain RAT & Chrome Credential Theft

**Status:** DRAFT — pending peer review and editorial pass
**Date:** 2026-06-25
**Analyst:** Actioner (automated)
**TLP:** CLEAR

---

## Executive Summary

Three malicious npm packages — `postcss-minify-selector-parser`, `postcss-minify-selector`, and `aes-decode-runner-pro` — typosquat the legitimate `postcss-selector-parser` library (150M+ weekly downloads) to deliver a multi-stage Windows RAT. Discovered by [JFrog Security Research](https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/) on 2026-06-22, the attack uses AES-256-GCM encrypted JavaScript droppers, PowerShell downloaders, and Nuitka-compiled Python modules to establish persistence, exfiltrate Chrome credentials (bypassing App-Bound Encryption), and maintain C2 communications. Combined downloads across the three packages totaled approximately 1,016.

## Sources

| Source | URL |
|--------|-----|
| JFrog Security Research (Primary) | [From PostCSS Typosquat to Windows RAT](https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/) |
| The Hacker News | [Malicious npm Packages Pose as PostCSS Tools](https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html) |
| Hackread | [Fake npm Packages Impersonate PostCSS Tool](https://hackread.com/fake-npm-packages-postcss-tool-steal-chrome-password/) |
| Infosecurity Magazine | [Lookalike npm Package Hides Multi-Stage Windows RAT](https://www.infosecurity-magazine.com/news/lookalike-npm-package-postcss/) |

## Affected Packages

| Package Name | XRAY ID | Downloads | Publisher |
|---|---|---|---|
| `postcss-minify-selector-parser` | XRAY-1002983 | ~615 | `abdrizak` |
| `postcss-minify-selector` | XRAY-1003986 | ~256 | `abdrizak` |
| `aes-decode-runner-pro` | XRAY-989675 | ~145 | `abdrizak` |

**Impersonated package:** `postcss-selector-parser` (legitimate, 150M+ weekly downloads)

## Attack Chain

```
npm install (typosquat)
  └─> index.js → require('src/config/defaults.js')
       └─> AES-256-GCM decryption of embedded blob
            └─> JavaScript dropper
                 └─> writes settings.ps1 (../../settings.ps1)
                      └─> PowerShell -NoProfile -ExecutionPolicy Bypass -File settings.ps1
                           └─> curl.exe downloads hxxp[:]//nvidiadriver[.]net/verv1432/winpatch-xd7d[.]win
                                └─> Saved as %TEMP%\winPatch.zip → Expand-Archive
                                     └─> wscript.exe %TEMP%\winPatch\update.vbs
                                          └─> Python 3.10 environment (hidden)
                                               └─> loader.py → Nuitka .pyd modules
                                                    └─> RAT → C2 at 95[.]216[.]92[.]207:8080
```

## Indicators of Compromise (Defanged)

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| Domain | `nvidiadriver[.]net` | Payload delivery, masquerades as NVIDIA driver site |
| URL | `hxxp[:]//nvidiadriver[.]net/verv1432/winpatch-xd7d[.]win` | ZIP payload download |
| IP:Port | `95[.]216[.]92[.]207:8080` | C2 server (HTTP POST, binary octet-stream) |

### File Artifacts

| Path | Description |
|------|-------------|
| `../../settings.ps1` (relative to package) | PowerShell dropper script |
| `%TEMP%\winPatch.zip` | Downloaded payload archive |
| `%TEMP%\winPatch\` | Extracted payload directory |
| `%TEMP%\winPatch\update.vbs` | VBScript executor |
| `%TEMP%\.store` | Single-instance tracking file |
| `%TEMP%\.host` | Victim UUID storage |

### Compiled Python Modules (SHA-256)

| Module | Hash | Purpose |
|--------|------|---------|
| `audiodriver.cp310-win_amd64.pyd` | `164e322d6fbc62e254d73583acd7f39444c884d3f5e6a5d27db143fc25bc88b3` | RAT orchestration loop |
| `api.cp310-win_amd64.pyd` | `50ffce607867d8fa8eaf6ef5cd25a3c0e7e4415e881b9e55c04a67bcddb74fdf` | HTTP C2 comms (RC4/ARC4) |
| `auto.cp310-win_amd64.pyd` | `17832aa629524ef6e8d8d6e9b6b902a8d324b559e3c36dbd0e221ab1690be871` | Chrome credential/extension theft |
| `command.cp310-win_amd64.pyd` | `c8075bbff748096e1c6a1ea0aa67bb6762fdd7551427a12425b35b94c1f1ecf2` | Host profiling, VM checks, file transfer, shell |
| `config.cp310-win_amd64.pyd` | `f6669bd504ce6b0e303be7ee47f2ebbc062989c88c41f0a3f436044a24869798` | Constants, C2 URL, registry keys, command IDs |
| `util.cp310-win_amd64.pyd` | `282b9bc318ad1234cbd1b86424b784299b8be31545802a7c6b751166b814b990` | Archive helpers (tar/gzip) |

### Registry Persistence

| Key | Value Name | Description |
|-----|------------|-------------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `csshost` | RAT persistence at logon |

### Chrome Theft Details

- Target database: `Login Data`
- SQL query: `SELECT origin_url, username_value, password_value, date_created FROM logins`
- Decryption APIs: DPAPI, `NCryptOpenStorageProvider`, `NCryptOpenKey`, `NCryptDecrypt`
- Chrome encryption marker: `Google Chromekey1`
- Crypto: ChaCha20_Poly1305, AES-GCM (bypasses App-Bound Encryption)
- Exfil artifacts: `gather.tar.gz`, `pwd.txt`, `chrome_logins_dump.txt`

### VM Detection

- WMI queries for: vmware, virtualbox, kvm, qemu, hyper-v
- MAC prefix checks: `00:05:69`, `00:0c:29`, `00:50:56`, `08:00:27`, `00:15:5d`

### C2 Protocol

- Transport: HTTP POST to `95[.]216[.]92[.]207:8080`
- Content-Type: `application/octet-stream`
- Encryption: RC4/ARC4-wrapped packets with MD5 checksum validation

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detail |
|--------|-----------|-----|--------|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Typosquatting legitimate npm packages |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | settings.ps1 with -ExecutionPolicy Bypass |
| Execution | Command and Scripting Interpreter: Visual Basic | T1059.005 | update.vbs via wscript.exe |
| Execution | Command and Scripting Interpreter: Python | T1059.006 | loader.py launching .pyd modules |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | HKCU Run key "csshost" |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | AES-256-GCM encrypted JavaScript dropper |
| Defense Evasion | Virtualization/Sandbox Evasion: System Checks | T1497.001 | VM detection via WMI and MAC prefixes |
| Defense Evasion | Modify Registry | T1112 | Registry Run key creation |
| Credential Access | Credentials from Password Stores: Credentials from Web Browsers | T1555.003 | Chrome Login Data extraction via DPAPI/NCrypt |
| Collection | Data from Local System | T1005 | Chrome extension data, host info |
| Collection | Archive Collected Data | T1560 | gather.tar.gz packaging |
| Command and Control | Ingress Tool Transfer | T1105 | curl.exe download of winPatch.zip |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP POST binary C2 |
| Command and Control | Encrypted Channel: Symmetric Cryptography | T1573.001 | RC4/ARC4 C2 encryption |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Credential data sent over C2 |

## Viability Gate Assessment

| Criterion | Assessment |
|-----------|------------|
| **IOC specificity** | HIGH — Named packages, SHA-256 hashes, specific C2 IP:port, unique domain, distinctive registry value name, unique file paths |
| **TTP detectability** | HIGH — Multi-stage chain has several chokepoints (node.exe spawning PowerShell with bypass, wscript.exe launching from Temp, specific registry key name) |
| **Source quality** | HIGH — Primary source is JFrog Security Research with full technical decomposition; confirmed by 4+ secondary outlets |
| **Rule feasibility** | HIGH — Process creation, registry, file, and network rules all viable with low false-positive risk |
| **Verdict** | **PASS** — Proceed with PoC/advisory-specific rules |

## Detection Rules

### Sigma Rules

**File:** `rules/sigma/2026-06-25-npm-postcss-supply-chain.yml`

#### Rule 1: PowerShell Dropper Execution (ID: a7c3e1f0)

Detects node.exe spawning PowerShell with `-ExecutionPolicy Bypass` to execute `settings.ps1`, or curl.exe downloading from nvidiadriver.net, or wscript.exe launching update.vbs from the winPatch directory. This is highly specific to the observed attack chain with minimal false-positive risk.

- **Compile status:** PASS (sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0)
- **Confidence:** HIGH
- **Caveat:** sigma check could not complete due to MITRE ATT&CK data fetch failure in the environment; structural validation passed via successful backend conversion.

#### Rule 2: Registry Persistence via csshost (ID: b8d4f2a1)

Detects creation of the `csshost` Run key used for RAT persistence. The value name is distinctive and unlikely to appear in legitimate software.

- **Compile status:** PASS (sigma convert exit 0)
- **Confidence:** HIGH
- **Caveat:** Requires Sysmon or equivalent registry monitoring with EventID 13 visibility.

#### Rule 3: Temp Directory File Artifacts (ID: c9e5a3b2)

Detects creation of winPatch files or the .store/.host tracking files in Temp directories. Broader than the other rules to catch payload staging behavior.

- **Compile status:** PASS (sigma convert exit 0)
- **Confidence:** MEDIUM
- **Caveat:** The `.store` and `.host` filename patterns in Temp directories could match unrelated software; tune or pair with other indicators.

### YARA Rules

**File:** `rules/yara/2026-06-25-npm-postcss-supply-chain.yar`

#### Rule 1: MAL_PostCSS_RAT_PYD_Modules

Detects the Nuitka-compiled .pyd modules by matching module filenames, C2 infrastructure strings, or the combination of the csshost registry key with Chrome credential query strings. All six .pyd hashes are listed in metadata for hash-based matching.

- **Compile status:** PASS (yarac exit 0)
- **Confidence:** HIGH
- **Caveat:** Requires PE files; will not fire on packed/encrypted payloads where strings are not in cleartext.

#### Rule 2: MAL_PostCSS_NPM_Dropper_JS

Detects the JavaScript dropper component by matching combinations of the settings.ps1 filename with the C2 domain, or the package name with AES decryption function references. Targets the npm package payload before extraction.

- **Compile status:** PASS (yarac exit 0)
- **Confidence:** HIGH
- **Caveat:** No PE header check — designed to match JavaScript files; may need filesystem scanning context.

#### Rule 3: MAL_PostCSS_RAT_Chrome_Stealer

Detects the auto.pyd Chrome credential theft module by matching Chrome-specific strings (Login Data paths, dump filenames) combined with NCrypt API references. Tuned to the specific ABE bypass technique.

- **Compile status:** PASS (yarac exit 0)
- **Confidence:** HIGH
- **Caveat:** Requires PE header; legitimate Chrome-interacting software could partially match — the condition requires multiple string groups to reduce false positives.

#### Rule 4: MAL_PostCSS_RAT_Settings_PS1

Detects the PowerShell dropper script by matching 3+ of: nvidiadriver.net domain, winPatch.zip filename, Expand-Archive cmdlet, curl.exe, update.vbs, or wscript references. Lightweight rule for scanning developer machines.

- **Compile status:** PASS (yarac exit 0)
- **Confidence:** MEDIUM
- **Caveat:** No file type restriction; the 3-of-6 threshold balances coverage vs. precision — consider raising to 4 in noisy environments.

### Suricata Rules

**File:** `rules/suricata/2026-06-25-npm-postcss-supply-chain.rules`

#### Rule 1: Payload Download from nvidiadriver.net (SID: 2026062501)

Alerts on HTTP requests to nvidiadriver.net with the /verv1432/ URI path used for payload delivery. Domain-specific and URI-specific for high fidelity.

- **Compile status:** PASS (suricata -T exit 0)
- **Confidence:** HIGH
- **Caveat:** Domain may be taken down or rotated; rule becomes a historical indicator.

#### Rule 2: C2 Communication to Known IP (SID: 2026062502)

Alerts on any TCP connection to 95.216.92.207:8080. Simple IP:port match for the known C2 endpoint.

- **Compile status:** PASS (suricata -T exit 0)
- **Confidence:** HIGH
- **Caveat:** IP-based rules have a limited shelf life; IP may be reassigned to legitimate services.

#### Rule 3: HTTP C2 Binary POST (SID: 2026062503)

Alerts on HTTP POST requests with `application/octet-stream` content type to the known C2 IP:port. More specific than the IP-only rule as it matches the observed C2 protocol behavior.

- **Compile status:** PASS (suricata -T exit 0)
- **Confidence:** HIGH
- **Caveat:** Dependent on the same C2 IP; combine with Rule 2 for defense-in-depth.

## Recommendations

1. **Immediate:** Scan npm dependency trees for `postcss-minify-selector-parser`, `postcss-minify-selector`, and `aes-decode-runner-pro`. Remove and rebuild if found.
2. **Credential rotation:** If any of the three packages were installed on a Windows machine, assume Chrome credentials are compromised. Rotate all passwords stored in Chrome and revoke sessions.
3. **Network:** Block `nvidiadriver[.]net` and `95[.]216[.]92[.]207` at perimeter firewalls and DNS resolvers.
4. **Registry:** Hunt for `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\csshost` across endpoints.
5. **File system:** Search for `%TEMP%\winPatch\`, `%TEMP%\.store`, and `%TEMP%\.host` artifacts.
6. **Long-term:** Implement npm package allow-listing or lockfile integrity checking (e.g., `npm audit signatures`, Socket.dev, or similar) to catch typosquat packages before installation.

---

*DRAFT — This report has not been peer-reviewed. IOCs are defanged in prose; detection rules use real values. All hashes and IOCs sourced from JFrog Security Research primary report.*
