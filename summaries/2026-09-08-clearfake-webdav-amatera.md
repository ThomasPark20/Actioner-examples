# Technical Analysis Report: ClearFake WebDAV Infection Chain Delivering Amatera Stealer, ZigCryptoStealer, and NetSupport Manager (2026-09-08)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-09-08
Version: 1.0 (DRAFT)

## Executive Summary

Cisco Talos disclosed an evolution of the ClearFake fake-CAPTCHA ("ClickFix") campaign that replaces earlier direct-download loaders with **WebDAV-hosted DLLs executed via `rundll32.exe`**, fetched from a randomized WebDAV subdomain and launched by ordinal export. Victims land on a compromised website carrying a malicious Cloudflare Worker injection; the page queries a BNB Smart Chain testnet smart contract (EtherHiding) to select an OS-specific payload contract, then presents a fake Google CAPTCHA that instructs the victim to paste and run a clipboard command in the Windows Run dialog. That command reconstructs a `pushd`/`rundll32`/`popd` sequence that mounts the WebDAV share and executes the DLL. Talos tracked **two parallel loader/branch variants** — internally named for their disguised export/entry artifacts, **"pf.ch"** and **"verification.google"** — both of which ultimately deploy the **Amatera stealer** (a heavily obfuscated, anti-analysis .NET/native hybrid stealer using TLS+ChaCha20-Poly1305 C2 and a `telegra.ph` dead-drop resolver), but diverge on secondary payloads: the "pf.ch" branch sideloads a NativeAOT loader through a legitimate Google Chrome component to drop **ZigCryptoStealer** (a Zig-language clipboard crypto-clipper using EtherHiding for C2 resolution) alongside a signed-but-vulnerable driver (**DCRCVDrv.sys**) used to terminate EDR processes (BYOVD), plus a Go-based reverse-TCP/Yamux proxy; the "verification.google" branch instead uses PowerShell with extensive sandbox/VM evasion checks to install **NetSupport Manager** (renamed `client32.exe` → `hypersnap.exe`) as a covert remote-access trojan with a hidden UI and an HTTP gateway C2.

The campaign is broad (dozens of rotating attacker domains observed via Cisco Umbrella DNS telemetry across 38–98 countries for individual C2 domains) and technically mature: exception-driven control flow, control-flow flattening, API hashing/module-export walking, DLL hollowing of `dbghelp.dll`, direct WoW64 syscalls, and on-chain C2 resolution (EtherHiding) all defeat static signatures and most sandboxes. Talos attributes the "verification.google" NetSupport branch to **UAT-10820** with moderate confidence. This report carries dense, durable artifacts — 20+ SHA-256 hashes, 40+ attacker domains, 4 C2 IPs, exact URLs, DLL/export names, driver device names, and license strings — so the viability gate **passes**, and detection rules are emitted across Sigma, YARA, Snort, and Suricata.

## Background: ClearFake / ClickFix Malvertising Ecosystem

ClearFake is a long-running malvertising/compromised-website framework that injects fake browser-update or CAPTCHA-verification overlays into legitimate sites (often via compromised CMS plugins or, in this iteration, a malicious Cloudflare Worker). It is a delivery mechanism, not a single payload family — operators have rotated through various stealers and RATs since 2023. The "ClickFix" social-engineering technique it popularized (instructing the victim to open the Run dialog and paste a pre-copied command) has since been copied broadly across the crimeware ecosystem, including by the unrelated but overlapping EVALUSION and IClickFix campaigns referenced in this report for shared NetSupport licensing artifacts. This report covers the specific September 2026 WebDAV-based execution refinement.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-30 to 2026-07-05 | ZigCryptoStealer C2 domain: `fd.gstats-api-contact.cc` (per on-chain `setData` history) |
| 2026-07-05 to 2026-07-09 | ZigCryptoStealer C2 domain: `pkg.vogueatelier.cc` |
| 2026-07-09 to 2026-07-12 | ZigCryptoStealer C2 domain: `kffd3.vogueatelier.cc` |
| 2026-07-12 to 2026-07-18 | ZigCryptoStealer C2 domain: `kffd3.vexlatech.cc` |
| 2026-07-18 to 2026-07-26 | ZigCryptoStealer C2 domain: `static.quorashift.cc` (DNS seen in 38 countries) |
| 2026-07-26 to 2026-07-30 | ZigCryptoStealer C2 domain: `lb.propertyfind.cc` (DNS seen in 98 countries; top sources US, Indonesia, Brazil, India, Egypt) |
| 2026-09-08 | Cisco Talos publishes the ClearFake WebDAV infection chain analysis and IOC repository |

## Root Cause: Initial Access Vector

Drive-by compromise of legitimate websites via malicious Cloudflare Worker injection (T1189), followed by user-execution social engineering (T1204.001). The injected JavaScript first queries a BNB Smart Chain **testnet** contract (`0x886d310Ac23e05EA705e24E513D19f53793832A9`) via `bsc-testnet-rpc.publicnode.com` to select an OS-specific secondary contract — Windows victims resolve `0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff`, macOS victims resolve `0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5` — an EtherHiding pattern that lets the operator update the served content on-chain without touching the compromised website. A fake Google CAPTCHA then instructs the victim to press Win+R, paste clipboard contents, and press Enter; the pasted command uses delayed environment-variable expansion to reassemble a `pushd \\<webdav-host>\DavWWWRoot\ ... rundll32.exe <dll>,#1 ... popd` sequence at runtime, evading command-line string signatures until execution.

## Technical Analysis of the Malicious Payload

### 1. WebDAV DLL Delivery and Execution (Stage 1 — both branches)

Two loader DLL variants were recovered, both executed as `rundll32.exe <path>,#1` (ordinal export) from a WebDAV UNC path (`\\<random-subdomain>\DavWWWRoot\...`):

- **"pf.ch" loader** — export name `moor`; WebDAV host is a randomized subdomain of `leaguejazire.com`; protections include exception-driven control flow, XOR loops, API hashing, and vectored exception handling (VEH); it waits on an event named `hit` and uses Windows fibers to transfer execution; unpacking combines XOR with LZNT1 decompression.
- **"verification.google" loader** — export name `CfgInspectModuleData`; WebDAV host is a randomized subdomain (exact naming pattern not recovered by Talos); protections include control-flow flattening, `TpAllocWork` threadpool-callback execution, and direct WoW64 syscalls; it achieves stealth via DLL hollowing/module stomping of the legitimate `dbghelp.dll`.

### 2. Primary Payload — Amatera Stealer

Both branches ultimately execute **Amatera stealer**. The "pf.ch" build self-identifies as version `4.1.5-alpha` with internal build label `GETWELL2`/`GETWELLV2`; it is 32-bit, ships with no import table, and resolves APIs by walking module export tables, using 32-to-64-bit transitions to invoke native syscalls (anti-hooking/anti-EDR evasion). Configuration/C2 resolution differs by branch:

- **"pf.ch" C2**: dead-drop resolver at `https://telegra.ph/Functions-04-03` returns a base64-encoded C2 IP (`MTQ1LjI0OS4xMDkuMTQ3` → `145.249.109.147`) over TCP/443 using TLS with ECDH key exchange and ChaCha20-Poly1305 payload encryption; the stealer's own configuration blob is base64-then-XOR'd with key `852149723\x00`. A `GetEndpoints` call returns randomized URI paths for further C2 functions.
- **"verification.google" C2**: bootstrap C2 IP `45.150.34.2` over TCP/443, using TLS SNI and HTTP Host header `github.com` to blend into legitimate traffic (domain fronting-style masquerade).

Amatera's exfiltration configuration contains 400+ rules spanning browser data (cookies/autofill/passwords), 100+ desktop cryptocurrency wallets, credential managers (KeePass, Bitwarden, 1Password, RoboForm, NordPass, WinAuth, Authy), FTP/mail/VPN clients (FileZilla, AnyDesk, NordVPN, AzireVPN), and a file grabber targeting Desktop/Downloads/Documents/Recent for `.kdbx`, `.p12`, `.pfx`, `.pem` files (wallet backups, private keys, 2FA seeds). A secondary-payload task array (`ld`) drives further downloads via JSON fields `u` (URL), `tf` (payload type: 1=EXE, 2=DLL, 3=command script, 4=PowerShell, 5=raw shellcode, 6=MSI), `tr` (execution type: 1=file-based, 2=fileless), and `p` (priority).

### 3. "pf.ch" Branch Secondary Payloads

**Task 1 — NativeAOT loader sideloading ZigCryptoStealer**: A downloaded archive (SHA-256 `279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92`) contains a legitimate Google Chrome component `platform_experience_helper.exe`, a malicious `Secur32.dll` (sideloaded by the legitimate EXE via DLL search-order hijacking), and the signed-but-vulnerable driver `DCRCVDrv.sys`. `Secur32.dll` decrypts and manually maps two PE payloads into a `C:\Windows\explorer.exe` process spawned in a suspended state (process hollowing: allocate, write, `SetThreadContext` to the new entry point, `ResumeThread`).

- **ZigCryptoStealer**: written in Zig; polls the clipboard and replaces cryptocurrency addresses with attacker-controlled ones across multiple address formats; C2 "configuration" is retrieved via an EtherHiding JSON-RPC (`eth_call`) lookup at RPC endpoint `bsc.rpc.blxrbdn.com` against BNB Smart Chain contract `0x7CC3cFC1Ac007B8c6566fD2C7419b15a75473468`, which returns the current operational domain via `setData`, disguised as a routine ERC-20 balance check. A randomly generated wallet address serves as the per-victim identifier.
- **DCRCVDrv.sys (BYOVD)**: a signed driver (vendor strings "MOCOMSYS" and "DCRC", product "DCRCV_U Driver") exposing device `\Device\DCRCVDRV_U`; IOCTL `0x2205c0` calls `ZwTerminateProcess` with no caller-authorization checks, letting user-mode malware terminate arbitrary processes (targeting EDR) by hashing running process names against an embedded target list.

**Task 2 — Go reverse-TCP/Yamux proxy**: shellcode (SHA-256 `643ef35536ff9273fb84b8504467b1a5645cd3ffd5476d64b99244b02131b205`) unpacks to a Go binary (SHA-256 `1819827e17f31e72d456158b6b9c90af25a65945f6f05d04a060da9f24179b25`) built from package path `github.com/acr/proxy-panel/cmd/bot`, using HashiCorp's Yamux multiplexing library over a WebSocket-Secure connection to `wss://update.dubbedmuch.cc/`. It sends the host's `MachineGuid` and hostname, then multiplexes bidirectional relay streams — turning the victim into a network proxy/pivot point for the operator.

### 4. "verification.google" Branch — NetSupport Manager Deployment

PowerShell fetches and `Invoke-Expression`s a script (`https://kr.cedar2glanz.ru/jewel.js`) via `DownloadString`. Before deploying anything, the script runs a layered sandbox/VM check: C: volume-serial comparison against a hard-coded bypass value `4E014A2F`; system-uptime floor (<10 minutes exits); a `NtDelayExecution`/`GetTickCount64` timing-acceleration check (measured <400ms for a requested 500ms delay indicates a VM/sandbox); logical processor count (<3 unexpectedly *allows* execution); physical RAM floor (<3.2 GiB fails); video RAM floor (<384 MiB fails); and a 36-entry deny-list of virtual/cloud GPU adapter name strings. In parallel, decoy PowerShell runspaces issue legitimate-looking requests to GitHub, npm, Docker Hub, PyPI, NuGet, and PowerShell Gallery to blend with developer-tool telemetry.

On success, it downloads a ZIP (`https://phys.stunned-amniotic.com/hub.log`, SHA-256 `bd36f4c15fe0acb6748da5ed12e45dcc37d412385812c078d1e4f04730e9f69b`) containing the genuine NetSupport Manager client (`client32.exe` v12.44) renamed to `hypersnap.exe`, importing `PCICL32.DLL` (export `_NSMClient32@8`). A dropped `client32.ini` configures: silent operation, hidden system-tray icon, disabled chat/message/disconnect/replay/help controls, HTTP Gateway `paternal-angrily.com:443` (resolved at analysis time to `212.118.56.166`, Russia-hosted), and a 60-second poll interval. The license string `KAKAN` / serial `NSM789508` embedded in the config also appears in the unrelated **EVALUSION** and **IClickFix** campaigns, suggesting shared tooling or a common access broker. Execution is started hidden via a scheduled task triggered at user logon.

### 5. Anti-Forensics / Evasion Techniques

- Exception-driven control flow, vectored exception handling, and control-flow flattening in both loader DLLs defeat static disassembly and signature matching.
- API hashing / export-table walking (no import table) defeats import-based static detection.
- DLL hollowing / module stomping of legitimate `dbghelp.dll` and DLL sideloading via a genuine Chrome component (`platform_experience_helper.exe`) abuse trusted-binary allowlisting.
- BYOVD via `DCRCVDrv.sys` directly disables EDR by terminating its processes at the kernel/IOCTL layer, bypassing user-mode tamper protection.
- EtherHiding (both the initial OS-selection contract and ZigCryptoStealer's C2 resolution) hides operational infrastructure behind an immutable, difficult-to-take-down blockchain read, with traffic disguised as routine ERC-20 balance/token calls.
- NetSupport branch: multi-layered VM/sandbox detection (volume serial, uptime, timing-acceleration, RAM/VRAM floors, GPU adapter name deny-list) plus decoy traffic to legitimate developer services to defeat both automated sandboxes and network-behavior analysts.
- Domain-fronting-style TLS SNI/HTTP Host masquerade as `github.com` for the "verification.google" Amatera C2.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`, `c2[.]attacker[.]net`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`, `192.168[.]1[.]100`)

### File System

| Platform | Path / Name | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | (WebDAV DLL, "pf.ch") | — | rundll32-executed ordinal-1 export `moor` |
| Windows | (WebDAV DLL, "verification.google") | — | rundll32-executed ordinal-1 export `CfgInspectModuleData` |
| Windows | NativeAOT/ZigCryptoStealer/DCRCVDrv.sys archive | `279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92` | Contains `platform_experience_helper.exe`, `Secur32.dll`, `DCRCVDrv.sys` |
| Windows | Go reverse-proxy shellcode | `643ef35536ff9273fb84b8504467b1a5645cd3ffd5476d64b99244b02131b205` | Packed Yamux/wss proxy shellcode |
| Windows | Go reverse-proxy unpacked binary | `1819827e17f31e72d456158b6b9c90af25a65945f6f05d04a060da9f24179b25` | `github.com/acr/proxy-panel/cmd/bot` |
| Windows | NetSupport delivery ZIP | `bd36f4c15fe0acb6748da5ed12e45dcc37d412385812c078d1e4f04730e9f69b` | Contains `hypersnap.exe` (renamed `client32.exe` v12.44) |
| Windows | `Secur32.dll` (NativeAOT loader) | see Talos IOC list | Sideloaded via Chrome component DLL search-order hijack |
| Windows | `DCRCVDrv.sys` | see Talos IOC list | Signed vulnerable driver; device `\Device\DCRCVDRV_U`; BYOVD |
| Windows | `hypersnap.exe` | — | Renamed NetSupport Manager `client32.exe`; `OriginalFileName` = `client32.exe` |
| Windows | `client32.ini` | — | NetSupport config: Gateway `paternal-angrily[.]com:443`, license `KAKAN`/`NSM789508` |

**Additional published SHA-256 hashes** (Talos IOC repository, roles not individually attributed in the blog text): `88735b838a83428193d1909424d082339cc1a993a4f91a9df09f51c81c69f70a`, `9f7b6aa8bd4c726a9a8d4c2788814db417a21cf4a7f9de3e1fc2bca6203a4e14`, `10f411e530c7bd86583ce80977d795837d85bab6b3ecb01fe3f3d069cdaeca8e`, `20040a8d6389a1a638c39b5457f235b2c23efa8bbd9f98204db831d5e3dc9b66`, `15fea063a3ceba5e929536357d1e9e1b9f0326fcbec50d570c4583712b109d6f`, `c2256961d9b7704e2bb85ae9512b4c1ee75fea95532434230c93cd5e38ef8aa7`, `38e74ff8d5f02617ff8858d9094b455d4e999223c7f78726584690e7201d94b7`, `91c4e9537558ef4481e5ea29c785fd1bc3f162bb60e2fa313239957e4381cacf`, `87e8d39db624f37d3e77aedf487a2dfd197f71a4730ea74f4e7a4341deaec2ff`, `7504898b17a9ce05eb9209128bcd0fb67d675a70c8c64f6f624d08b47b2fe3af`, `9aa88b8e5b298e78ebd55ad53d322efe4b26e6cb1fadf6e94ae258d62a3362e4`, `0d660045808528c0525313b148f649eb77a341a2a2f8c5641721551362aa73d0`, `0c9bb4ced6c55776b0b2b903b4f65f2653d5868214601a4dcceea27789701dd5`, `be028ac6299ce6c2870941c700fa1fb2581bfd4ee6c0c75e89c5da9cea73fe97`, `abd28aecb2d57660bcd9455333b84d289aa883eaf5cf15def1bf0feb35833aa2`, `93830d73ddf9665ae4d5665f1cebabd093646ed54356662e1b2a925bc2df681b`, `86fbce191248bcc124b1259a178d84216d713f4acd516f578c5f3fdccb01fa4a`, `264c87880f7afaeb02e0fa522db52294d5a4198ae97fcf67d9aace3474c1b62f`

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `leaguejazire[.]com` | WebDAV DLL hosting, "pf.ch" branch (randomized subdomains) |
| Domain | `fd[.]gstats-api-contact[.]cc`, `mgo[.]gstats-api-contact[.]cc`, `fd[.]gstats-api-contd[.]cc`, `xn--b1aluem3j[.]gstats-api-contd[.]cc`, `xn--i-ctbr1afp[.]gstats-api-contd[.]cc`, `xn--b1ahgbfifq[.]gstats-api-cont[.]co`, `sp13[.]gstats-api-cont[.]co`, `sp13[.]gstats-api-coni[.]co`, `sp1[.]gstats-api-coni[.]co` | ZigCryptoStealer EtherHiding C2 rotation |
| Domain | `pkg[.]vogueatelier[.]cc`, `kffd3[.]vogueatelier[.]cc`, `kffd3[.]vexlatech[.]cc`, `static[.]quorashift[.]cc`, `lb[.]propertyfind[.]cc` | ZigCryptoStealer C2 rotation (dated, see Timeline) |
| Domain | `fd-api-zog[.]velqo7[.]co`, `fd-api-rop[.]velqo7[.]co`, `fd-api-irc[.]velqo7[.]co`, `fd-api-irs[.]velqo7[.]co`, `fd-api-iris[.]velqo7[.]co`, `wix[.]velqo7[.]co`, `wdx[.]velqo7[.]co`, `wdm[.]velqo7[.]co` | Related C2 rotation infrastructure |
| Domain | `wdm[.]unguidedfreewill[.]co`, `wdx[.]unguidedfreewill[.]co`, `sdx[.]unguidedfreewill[.]co`, `fgp[.]unguidedfreewill[.]co`, `jup[.]unguidedfreewill[.]co`, `dmt[.]unguidedfreewill[.]co`, `tnt[.]unguidedfreewill[.]co` | Related C2 rotation infrastructure |
| Domain | `paf[.]hugo-mapp[.]co`, `pf[.]hugo-mapp[.]co`, `fr[.]hugo-mapp[.]co`, `en[.]hugo-mapp[.]co`, `dau[.]hugo-mapp[.]co`, `doh[.]hugo-mapp[.]co`, `smart[.]hugo-mapp[.]co`, `br[.]hugo-lapp[.]co`, `pt[.]hugo-lapp[.]co` | Related C2 rotation infrastructure |
| Domain | `geo[.]estimator-undermostshelving[.]in[.]net` | Second-stage / config host |
| Domain | `update[.]dubbedmuch[.]cc` | Go reverse-proxy WSS C2 |
| Domain | `kr[.]cedar2glanz[.]ru` | NetSupport PowerShell stager host (`jewel.js`) |
| Domain | `phys[.]stunned-amniotic[.]com` | NetSupport delivery ZIP host (`hub.log`) |
| Domain | `paternal-angrily[.]com` | NetSupport HTTP Gateway C2 |
| Domain | `riyazinikokar[.]xyz`, `metrics.demobunfiber[.]top` | Additional Talos-published campaign domains |
| IP | `145.249.109[.]147:443` | Amatera "pf.ch" C2 (resolved via telegra.ph dead-drop) |
| IP | `45.150.34[.]2:443` | Amatera "verification.google" bootstrap C2 (SNI/Host `github.com`) |
| IP | `212.118.56[.]166:443` | NetSupport Manager HTTP Gateway (Russia) |
| IP | `150.241.94[.]112` | Additional Talos-published campaign IP |
| URL | `hxxps://telegra[.]ph/Functions-04-03` | Amatera "pf.ch" dead-drop C2 resolver |
| URL | `hxxps://geo.estimator-undermostshelving[.]in[.]net/dc06681a3f4e` | Second-stage component |
| URL | `hxxps://geo.estimator-undermostshelving[.]in[.]net/jquery.min.js` | Second-stage component (disguised filename) |
| URL | `wss://update.dubbedmuch[.]cc/` | Go reverse-proxy WebSocket C2 |
| URL | `hxxps://kr.cedar2glanz[.]ru/jewel.js` | NetSupport branch PowerShell stager |
| URL | `hxxps://phys.stunned-amniotic[.]com/hub.log` | NetSupport delivery ZIP |
| URL | `hxxps://www.mediafire[.]com/file_premium/uoixtb8zxevpi6e/vk_swiftshader_icd.dat/file` | Additional hosted component |

### Behavioral

`rundll32.exe` executing a DLL from a WebDAV UNC path (`\\<host>\DavWWWRoot\...`) with ordinal export `#1` (exports observed: `moor`, `CfgInspectModuleData`); a PowerShell process performing `DownloadString`+`Invoke-Expression` against attacker infrastructure followed by multi-second timing/environment checks and background requests to package-registry domains; a process whose PE `OriginalFileName` is `client32.exe` but whose on-disk file name is not (masquerading NetSupport Manager); Chrome-signed `platform_experience_helper.exe` loading a `Secur32.dll` from a non-standard, non-system directory; `explorer.exe` spawned in a suspended state and subsequently written to/resumed by a parent other than the shell (process-hollowing indicator); a kernel driver load event for `DCRCVDrv.sys` followed by termination of security-product processes; JSON-RPC (`eth_call`) HTTP/HTTPS POST traffic to BNB Smart Chain RPC endpoints (`bsc-testnet-rpc.publicnode.com`, `bsc.rpc.blxrbdn.com`) from unexpected desktop processes.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1189 | Drive-by Compromise | Malicious Cloudflare Worker injected into compromised websites |
| T1204.001 | User Execution: Malicious Link | Fake CAPTCHA / ClickFix prompt instructs manual Run-dialog paste-and-execute |
| T1218.011 | Signed Binary Proxy Execution: Rundll32 | `rundll32.exe <webdav-path>,#1` launches both loader DLL variants |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | `Secur32.dll` sideloaded by legitimate `platform_experience_helper.exe` (search-order hijack) and legitimate `dbghelp.dll` hollowed/module-stomped by the "verification.google" loader |
| T1055.012 | Process Injection: Process Hollowing | Manual PE mapping into a suspended `explorer.exe` |
| T1027 | Obfuscation of Files or Information | XOR, LZNT1, control-flow flattening, API hashing, no import table |
| T1140 | Deobfuscation/Decoding of Files or Information | Multi-layer XOR/base64 decoding of C2 configuration and IP |
| T1027.007 | Dynamic API Resolution | Amatera resolves APIs via export-table walking, no static import table |
| T1562.001 | Impair Defenses: Disable or Modify Tools | `DCRCVDrv.sys` BYOVD used to `ZwTerminateProcess` EDR processes |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | NetSupport stager: volume serial, uptime, timing, RAM/VRAM, GPU adapter checks |
| T1071.004 | Application Layer Protocol: DNS (EtherHiding via on-chain RPC lookups) | OS-selection and ZigCryptoStealer C2 resolved via BNB Smart Chain `eth_call` |
| T1568 | Dynamic Resolution | Dead-drop resolver (`telegra.ph`) and rotating C2 subdomains |
| T1005 | Data from Local System | Amatera file-grabber targeting Desktop/Downloads/Documents/Recent |
| T1555 | Credentials from Password Stores | Amatera targets KeePass, Bitwarden, 1Password, RoboForm, NordPass, WinAuth, Authy |
| T1115 | Clipboard Data | ZigCryptoStealer clipboard polling and cryptocurrency-address replacement |
| T1105 | Ingress Tool Transfer | Secondary-payload downloads (NativeAOT archive, Go proxy shellcode, NetSupport ZIP) |
| T1219 | Remote Access Software | NetSupport Manager installed and configured for covert remote control |
| T1036.005 | Masquerading: Match Legitimate Name or Location | `client32.exe` renamed to `hypersnap.exe` |
| T1053.005 | Scheduled Task/Job: Scheduled Task | NetSupport client started hidden via logon-triggered scheduled task |
| T1041 | Exfiltration Over C2 Channel | Amatera stealer TLS/ChaCha20-Poly1305 exfil channel |
| T1571 | Non-Standard Port | Amatera and NetSupport C2 use TCP/443 for non-HTTPS application protocol |

## Impact Assessment

Breadth is significant at the infrastructure level: Cisco Umbrella DNS telemetry shows individual ZigCryptoStealer C2 domains resolved from **38 to 98 countries**, with `lb.propertyfind.cc` topping sources in the US, Indonesia, Brazil, India, and Egypt — indicating this is a high-volume, geographically dispersed campaign rather than a targeted operation. Depth of impact per victim is high: successful execution yields full credential/wallet/session theft (Amatera), silent cryptocurrency-transaction hijacking (ZigCryptoStealer), EDR blinding (DCRCVDrv.sys BYOVD), a persistent covert RAT (NetSupport Manager), and potential conscription as a network relay (Go/Yamux proxy) — a near-complete compromise chain from a single clipboard paste. Stealth is high: multiple anti-analysis layers (control-flow flattening, VEH, module stomping, sandbox-timing checks, EtherHiding) are purpose-built to defeat both static AV/EDR signatures and automated dynamic sandboxes, and the WebDAV delivery mechanism means the malicious DLL is never written to disk as a discrete downloaded file in the way legacy loaders were, reducing file-based detection surface.

## Detection & Remediation

### Immediate Detection

- Hunt Sysmon/EDR process-creation telemetry for `rundll32.exe` with a `CommandLine` containing `DavWWWRoot` — this string is diagnostic of WebDAV-redirector execution and is rare in legitimate environments.
- Query DNS/proxy logs for any of the domains listed in the Network IOC table above, and for the `telegra.ph/Functions-04-03` and `kr.cedar2glanz.ru/jewel.js` URLs specifically.
- Search endpoint file inventories / EDR for any binary whose PE `OriginalFileName` is `client32.exe` but whose on-disk name is not `client32.exe` (flags renamed NetSupport Manager, including `hypersnap.exe`).
- Check loaded-driver inventories (`driverquery`, EDR driver-load telemetry) for `DCRCVDrv.sys` or a device object `\Device\DCRCVDRV_U`.
- Review scheduled tasks triggered "at logon" that launch an unsigned or renamed binary from user-writable paths.

### Remediation

1. **Contain**: Isolate any host that resolved the listed domains, executed `rundll32.exe ...,DavWWWRoot...`, or shows `DCRCVDrv.sys` loaded.
2. **Eradicate**: Remove the NetSupport Manager installation (binary + `client32.ini` + scheduled task), unload and delete `DCRCVDrv.sys`, terminate and remove the Go/Yamux proxy process, and remove the `Secur32.dll`/`platform_experience_helper.exe` sideload pair.
3. **Recover credentials**: Treat any host that ran Amatera as fully compromised for browser-stored credentials, cookies, and session tokens; force logout of all sessions and rotate passwords, API keys, and stored credential-manager vaults (KeePass, Bitwarden, 1Password, RoboForm, NordPass) accessed from that host.
4. **Recover wallets**: For any cryptocurrency wallet software present, assume seed/key exposure (Amatera file grabber) and clipboard-hijack exposure (ZigCryptoStealer) — migrate funds to newly generated wallets from a known-clean device.
5. **Driver hygiene**: Add `DCRCVDrv.sys` to a Windows Defender Application Control / driver blocklist (Microsoft's vulnerable-driver blocklist mechanism) to prevent BYOVD reuse even after removal.

### Long-Term Hardening

- Disable the WebDAV Client service (`WebClient`) on endpoints that have no legitimate business need for it — this single control breaks the entire `rundll32.exe ...,DavWWWRoot...` execution chain.
- Restrict or log Run-dialog (`Win+R`) usage patterns and educate users that no legitimate CAPTCHA or verification step ever requires pasting and running a command.
- Deploy attack-surface-reduction / application-control policy to block `rundll32.exe` from loading DLLs over SMB/WebDAV UNC paths.
- Maintain and enforce a current Microsoft vulnerable-driver blocklist to close the BYOVD path generically, not just for this one driver.
- Monitor outbound JSON-RPC (`eth_call`) traffic to public blockchain RPC endpoints from non-browser, non-wallet processes as a general EtherHiding detection heuristic.

## Detection Rules

<!-- audit(global): All Sigma rules fail `sigma check` with the same offline HTTP 403 fetching MITRE ATT&CK/D3FEND tactic data (RuntimeError in pySigma's mitre_attack loader) — this environment has no outbound access to that endpoint. It is NOT a rule defect: every rule's YAML parses, and both `sigma convert --without-pipeline -t splunk` and `-t log_scale` succeeded cleanly for all four rules (shown per-rule below). All 3 YARA rules compiled clean with `yarac <rule>.yar /dev/null` (exit 0). Snort rules were validated against the installed engine, which is Snort **2.9.20** (not Snort 3 as the reference doc assumes) via `snort -c /etc/snort/snort.conf -T` with the rule content staged into /etc/snort/rules/local.rules (Snort 2 has no -R rules-file flag; -R means pid-suffix) and restored afterward — required reformatting to single-line rules (Snort 2's parser does not accept unescaped multi-line rule bodies) and swapping the `http` service-header form (Snort-3-only) for `tcp $HTTP_PORTS` with post-content `http_method`/`http_header`/`http_uri` buffer-selector keywords, which Snort 2.9.20 supports. Suricata rules validated with `suricata -T -S <file>.rules -l <dir>` on Suricata 7.0.3 (exit 0 after removing a redundant `nocase` on an already-lowercased `http.host` buffer, and after switching to single-line rule bodies — Suricata 7.0.3 also rejected the multi-line body used in the reference doc's own examples). All values in the rules below are the real (non-defanged) indicators. -->

These 11 rules cover the chain's most durable, campaign-specific artifacts: WebDAV-based rundll32 execution and the NetSupport masquerade/PowerShell stager (Sigma), file-level strings/structure for the Amatera NativeAOT loader, ZigCryptoStealer, and the DCRCVDrv.sys BYOVD driver (YARA), and the published C2 IPs/domains/URLs (Snort, Suricata). The one caveat that matters across the set: this campaign rotates WebDAV and C2 subdomains on a roughly weekly cadence (see Timeline), so the DNS/network rules have a short shelf life and should be refreshed against the linked Talos IOC repository rather than treated as permanent blocklists.

### Sigma: Rundll32 execution of a DLL from a WebDAV UNC path
Detects `rundll32.exe` launching a DLL via a `DavWWWRoot` UNC path using an ordinal-1 or named export matching either observed loader variant.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: `sigma convert --without-pipeline -t splunk` => Image="*\rundll32.exe" CommandLine="*DavWWWRoot*" CommandLine IN ("*,#1*","*,moor*","*,CfgInspectModuleData*"); `-t log_scale` => equivalent regex form. Both exit 0. `DavWWWRoot` is the fixed marker the Windows WebDAV redirector inserts into any WebDAv UNC path, independent of which rotating subdomain is used, so this rule survives the campaign's domain rotation, unlike the DNS-based rules below. -->
```yaml
title: Rundll32 Execution of DLL from WebDAV UNC Path via DavWWWRoot
id: c17762cc-1809-4225-a87d-6972191b3393
status: experimental
description: >-
  Detects rundll32.exe launching a DLL hosted on a remote WebDAV share
  (identified by the DavWWWRoot marker in the UNC path) using an ordinal
  export, consistent with the ClearFake ClickFix chain that reconstructs a
  pushd/rundll32/popd command via clipboard paste to execute the "pf.ch" or
  "verification.google" Amatera stealer loader DLLs (Cisco Talos, 2026-09-08).
references:
  - https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
author: Actioner
date: 2026/09/08
tags:
  - attack.t1218.011
  - attack.t1570
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith: '\rundll32.exe'
  selection_webdav:
    CommandLine|contains: 'DavWWWRoot'
  selection_ordinal:
    CommandLine|contains:
      - ',#1'
      - ',moor'
      - ',CfgInspectModuleData'
  condition: selection_image and selection_webdav and selection_ordinal
falsepositives:
  - Legitimate administrative use of WebDAV-hosted DLLs (rare in most environments)
level: high
```

### Sigma: PowerShell download-and-execute of the NetSupport stager
Detects PowerShell using `DownloadString` combined with the campaign's specific stager hostname, paired with its own filename so a bare filename can never match against an unrelated host.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: splunk => Image IN ("*\powershell.exe","*\pwsh.exe") CommandLine="*DownloadString*" AND (("*cedar2glanz.ru*" AND "*jewel.js*") OR ("*stunned-amniotic.com*" AND "*hub.log*")); log_scale equivalent. Both exit 0. IOC-anchored (procedure-level), not a generic DownloadString+IEX heuristic, so false-positive risk is near zero but the rule expires when the operator rotates these specific hostnames. Revision: the domain and filename lists were previously flattened into one CommandLine|contains list, so a bare "jewel.js" or "hub.log" substring from ANY host (not just the campaign's) would satisfy selection_domain on its own — fixed by requiring each filename alongside its paired domain via two AND-gated sub-selections joined with OR. Level dropped from critical to high: this is still an IOC-anchored (not zero-day) detection, and "critical" should be reserved for rules with corroborating destructive/irreversible behavior (e.g. the driver-load + EDR-kill rule), not a download-cradle match alone. -->
```yaml
title: PowerShell Download and Execute of ClearFake NetSupport Manager Stager
id: f28e3d84-93d0-496c-aeaa-9bc2f9f09251
status: experimental
description: >-
  Detects PowerShell fetching and invoking the ClearFake "verification.google"
  branch second-stage script (jewel.js) via DownloadString/IEX, which performs
  extensive VM/sandbox checks before installing NetSupport Manager RAT
  disguised as hypersnap.exe (Cisco Talos, 2026-09-08).
references:
  - https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
author: Actioner
date: 2026/09/08
tags:
  - attack.t1059.001
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection_ps:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_pattern:
    CommandLine|contains|all:
      - 'DownloadString'
  selection_domain_stager:
    CommandLine|contains|all:
      - 'cedar2glanz.ru'
      - 'jewel.js'
  selection_domain_zip:
    CommandLine|contains|all:
      - 'stunned-amniotic.com'
      - 'hub.log'
  condition: selection_ps and selection_pattern and (selection_domain_stager or selection_domain_zip)
falsepositives:
  - None expected; matches campaign-specific hostname/filename pairs
level: high
```

### Sigma: NetSupport Manager client32.exe masquerading under an alternate name
Detects the genuine NetSupport client (PE `OriginalFileName` = `client32.exe`) running under any file name other than `client32.exe`, catching the observed `hypersnap.exe` rename and any future rename by the same operator.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: splunk => OriginalFileName="client32.exe" NOT Image="*\client32.exe"; log_scale equivalent negated regex. Both exit 0. Medium confidence because legitimate NetSupport Manager deployments occasionally rebrand client32.exe for helpdesk purposes — pair with the network/behavioral rules for corroboration before treating an alert as malicious. -->
```yaml
title: NetSupport Manager client32.exe Masquerading Under Alternate Name
id: f70bd317-cd3c-4ea1-8e82-7980e83e9176
status: experimental
description: >-
  Detects execution of the NetSupport Manager remote-control client
  (client32.exe, per PE OriginalFileName) renamed to an unrelated file name
  such as hypersnap.exe, as observed in the ClearFake "verification.google"
  branch delivering NetSupport Manager RAT configured with a silent,
  hidden-tray HTTP gateway (Cisco Talos, 2026-09-08).
references:
  - https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
author: Actioner
date: 2026/09/08
tags:
  - attack.t1036.005
  - attack.t1219
logsource:
  category: process_creation
  product: windows
detection:
  selection_original:
    OriginalFileName: 'client32.exe'
  filter_expected_name:
    Image|endswith: '\client32.exe'
  condition: selection_original and not filter_expected_name
falsepositives:
  - Legitimate NetSupport Manager deployments that rename client32.exe for branding purposes
level: high
```

### Sigma: DNS query to ClearFake/Amatera/NetSupport infrastructure
Detects DNS resolution of any currently-known WebDAV, ZigCryptoStealer, Go-proxy, or NetSupport delivery/gateway domain from this campaign.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: splunk => QueryName IN (18 domain suffixes); log_scale equivalent regex-OR. Both exit 0. Medium confidence (not high) specifically because the ZigCryptoStealer domains rotate roughly weekly per the Timeline — refresh this list from the linked Talos IOC repo periodically rather than treating it as static. -->
```yaml
title: DNS Query to ClearFake WebDAV/Amatera/NetSupport Infrastructure
id: 150c05a4-3d76-4756-a934-d260c2e6b368
status: experimental
description: >-
  Detects DNS resolution of domains used as WebDAV DLL-hosting, ZigCryptoStealer
  EtherHiding C2, Go reverse-proxy C2, or NetSupport Manager delivery/gateway
  infrastructure in the ClearFake campaign delivering Amatera stealer,
  ZigCryptoStealer, and NetSupport Manager (Cisco Talos, 2026-09-08).
references:
  - https://blog.talosintelligence.com/clearfake-webdav-infection-chain/
  - https://raw.githubusercontent.com/Cisco-Talos/IOCs/refs/heads/main/2026/09/clearfake-webdav-infection-chain.txt
author: Actioner
date: 2026/09/08
tags:
  - attack.t1071.004
  - attack.t1568
logsource:
  category: dns_query
  product: windows
detection:
  selection:
    QueryName|endswith:
      - 'leaguejazire.com'
      - 'gstats-api-contact.cc'
      - 'gstats-api-contd.cc'
      - 'gstats-api-cont.co'
      - 'gstats-api-coni.co'
      - 'vogueatelier.cc'
      - 'vexlatech.cc'
      - 'quorashift.cc'
      - 'propertyfind.cc'
      - 'velqo7.co'
      - 'unguidedfreewill.co'
      - 'hugo-mapp.co'
      - 'hugo-lapp.co'
      - 'estimator-undermostshelving.in.net'
      - 'dubbedmuch.cc'
      - 'cedar2glanz.ru'
      - 'stunned-amniotic.com'
      - 'paternal-angrily.com'
  condition: selection
falsepositives:
  - None expected; all values are campaign-specific attacker-registered domains
level: high
```

### YARA: Amatera NativeAOT sideload loader ("pf.ch" branch)
Flags the NativeAOT loader (masquerading as `Secur32.dll`) by its build-label strings, XOR key, BYOVD device name, and process-hollowing API set.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: `yarac clearfake-amatera-nativeaot-loader.yar /dev/null` exit 0. Medium confidence: build-label/XOR-key strings are the strongest signal but were only recovered from the one archived sample (hash in meta); the API-combination fallback branch is generic process-hollowing and will false-positive on legitimate hollowing-capable software (installers, some AV) if it ever fires alone — it is gated behind 3-of-4 APIs plus the literal child-process string to reduce that. -->
```yara
rule Malware_Amatera_NativeAOT_Loader_Secur32
{
    meta:
        description = "Detects the ClearFake NativeAOT sideload loader (masquerading as Secur32.dll) that decrypts and manually maps the Amatera stealer / ZigCryptoStealer chain into a suspended explorer.exe process"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        hash = "279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92"
        severity = "high"

    strings:
        $build1 = "GETWELL2" ascii
        $build2 = "GETWELLV2" ascii
        $xorkey = "852149723" ascii
        $device = "\\Device\\DCRCVDRV_U" ascii wide
        $child   = "explorer.exe" ascii wide
        $api1 = "VirtualAllocEx" ascii fullword
        $api2 = "WriteProcessMemory" ascii fullword
        $api3 = "ResumeThread" ascii fullword
        $api4 = "SetThreadContext" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            1 of ($build*) or
            $xorkey or
            $device or
            (3 of ($api*) and $child)
        )
}
```

### YARA: ZigCryptoStealer clipboard clipper
Flags the Zig-language clipper by its EtherHiding RPC endpoint/contract address plus clipboard API usage, gated to PE files.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: `yarac clearfake-zigcryptostealer.yar /dev/null` exit 0. Medium: no sample hash was published for the ZigCryptoStealer binary itself (only for the containing archive, already covered by the NativeAOT-loader rule), so this rule is string/behavior-based rather than sample-validated; the RPC endpoint and contract address are the durable, campaign-specific signal, clipboard APIs are the corroborating behavioral gate. Revision: the original condition had no PE header check or filesize cap, so it could fire on any file (script, log, memory dump) carrying the strings, and the "$method and 1 of ($zigrt*)" branch alone was prone to matching a legitimate Zig-language Ethereum utility; added a `uint16(0) == 0x5A4D and filesize < 10MB` guard wrapping the existing logic to scope matches to plausible native Windows binaries. -->
```yara
rule Malware_ZigCryptoStealer_EtherHiding_Clipper
{
    meta:
        description = "Detects ZigCryptoStealer, a Zig-language clipboard-hijacking cryptocurrency clipper delivered by the ClearFake WebDAV chain that resolves its rotating C2 domain via an EtherHiding BNB Smart Chain JSON-RPC lookup"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        severity = "high"

    strings:
        $rpc      = "bsc.rpc.blxrbdn.com" ascii wide
        $contract = "0x7CC3cFC1Ac007B8c6566fD2C7419b15a75473468" ascii wide nocase
        $method   = "eth_call" ascii
        $zigrt1   = "zig_panic" ascii
        $zigrt2   = "ZigCompilerBug" ascii
        $clip1    = "CF_TEXT" ascii
        $clip2    = "GetClipboardData" ascii fullword
        $clip3    = "SetClipboardData" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (
                $rpc or $contract or ($method and 1 of ($zigrt*))
            )
            and
            2 of ($clip*)
        )
}
```

### YARA: DCRCVDrv.sys BYOVD driver
Flags the specific signed-but-vulnerable driver abused to terminate EDR processes via an unauthenticated IOCTL.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: `yarac clearfake-dcrcvdrv-byovd.yar /dev/null` exit 0. High confidence: device name \Device\DCRCVDRV_U and vendor strings are specific, low-prevalence artifacts of this one driver; the $ioctl hex pattern is the little-endian encoding of IOCTL 0x2205c0 (bytes C0 05 22 00) reported by Talos as the process-termination control code, included as corroboration, not sole trigger. -->
```yara
import "pe"

rule Malware_ClearFake_DCRCVDrv_BYOVD_Driver
{
    meta:
        description = "Detects the signed but vulnerable DCRCVDrv.sys driver abused in the ClearFake chain (Bring-Your-Own-Vulnerable-Driver) to terminate EDR processes via an unauthenticated ZwTerminateProcess IOCTL"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        severity = "critical"

    strings:
        $device  = "\\Device\\DCRCVDRV_U" ascii wide
        $dosdev  = "DCRCVDRV_U" ascii wide
        $vendor1 = "MOCOMSYS" ascii wide
        $vendor2 = "DCRC" ascii wide fullword
        $ioctl   = { C0 05 22 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            ($device or $dosdev) and
            (1 of ($vendor*) or $ioctl)
        )
}
```

### Snort: ClearFake/Amatera/NetSupport C2 and dead-drop network activity
Three rules: outbound contact to the published C2 IPs, a DNS query for the NetSupport gateway domain, and an HTTP GET to the Amatera dead-drop resolver on telegra.ph.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: validated on the installed engine, Snort 2.9.20 (not Snort 3), via `snort -c /etc/snort/snort.conf -T` with the rule body staged into /etc/snort/rules/local.rules and restored after the test -> "Snort successfully validated the configuration! Snort exiting" (exit 0). Snort 2.9.20 has no -R flag (that's a Snort 3 CLI addition; -R in 2.9.20 sets the pidfile suffix) and rejects a multi-line rule body without trailing backslash continuations, so rules are single physical lines. It also rejects "alert http ... any (" as a bare service header (Bad protocol: http) — that service-header syntax is Snort-3-only — so the HTTP rule uses "alert tcp ... $HTTP_PORTS" with post-content http_method/http_header/http_uri buffer-selector keywords, which Snort 2.9.20's http_inspect preprocessor supports. DNS label length-prefix verified: "paternal-angrily" = 16 bytes = 0x10, "com" = 3 bytes = 0x03. IPs/URL are real (non-defanged) per spec. -->
```
alert ip $HOME_NET any -> [145.249.109.147,45.150.34.2,212.118.56.166,150.241.94.112] any (msg:"Actioner - Outbound Contact to ClearFake/Amatera/NetSupport C2 IP"; flow:to_server; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; classtype:trojan-activity; metadata:author Actioner, created 2026-09-08; sid:2100901; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"Actioner - DNS Query for ClearFake NetSupport Manager Gateway Domain paternal-angrily.com"; content:"|10|paternal-angrily|03|com|00|", nocase, fast_pattern; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; classtype:trojan-activity; metadata:author Actioner, created 2026-09-08; sid:2100902; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Actioner - HTTP Request to Amatera Stealer Dead-Drop Resolver on telegra.ph"; flow:established,to_server; content:"GET", nocase; http_method; content:"telegra.ph"; http_header; content:"/Functions-04-03", fast_pattern; http_uri; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; classtype:trojan-activity; metadata:author Actioner, created 2026-09-08; sid:2100903; rev:1;)
```

### Suricata: ClearFake/Amatera/NetSupport C2 and dead-drop network activity
Four rules: TLS SNI to the WebDAV DLL-hosting domain, outbound contact to the published C2 IPs, an HTTP GET to the Amatera dead-drop resolver, and TLS SNI to the Go reverse-proxy WSS C2.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: `suricata -T -S clearfake-c2-network.rules -l /tmp/actioner/suricata_test` on Suricata 7.0.3 -> "Configuration provided was successfully loaded. Exiting." (exit 0), after two fixes: (1) reformatted to single physical lines per rule — Suricata 7.0.3 rejected the multi-line parenthesized body (the same style used in this ref doc's own examples) with "no rule options" parse errors; (2) removed a redundant nocase on http.host (sid 2200903) — Suricata warned the hostname buffer is already lowercase-normalized. sid 2200901/2200904 use tls.sni + endswith to scope to the exact registrable domain regardless of the campaign's randomized WebDAV subdomain prefix. Domains/IPs/URL are real (non-defanged) per spec. -->
```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - TLS Connection to ClearFake WebDAV DLL-Hosting Domain leaguejazire.com"; flow:established,to_server; tls.sni; content:"leaguejazire.com"; endswith; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; classtype:trojan-activity; metadata:author Actioner, created_at 2026-09-08; sid:2200901; rev:1;)

alert ip $HOME_NET any -> [145.249.109.147,45.150.34.2,212.118.56.166,150.241.94.112] any (msg:"Actioner - Outbound Contact to ClearFake/Amatera/NetSupport C2 IP"; flow:to_server; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; classtype:trojan-activity; metadata:author Actioner, created_at 2026-09-08; sid:2200902; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - HTTP Request to Amatera Stealer Dead-Drop Resolver on telegra.ph"; flow:established,to_server; http.method; content:"GET"; http.host; content:"telegra.ph"; http.uri; content:"/Functions-04-03"; fast_pattern; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; classtype:trojan-activity; metadata:author Actioner, created_at 2026-09-08; sid:2200903; rev:1;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - WSS Connection to ClearFake Go Reverse-Proxy C2 update.dubbedmuch.cc"; flow:established,to_server; tls.sni; content:"update.dubbedmuch.cc"; endswith; reference:url,blog.talosintelligence.com/clearfake-webdav-infection-chain/; classtype:trojan-activity; metadata:author Actioner, created_at 2026-09-08; sid:2200904; rev:1;)
```

## Lessons Learned

This campaign demonstrates three converging trends defenders need to plan for rather than treat as one-offs. First, **execution-from-network-share** (WebDAV via `rundll32.exe`) is displacing "download-then-execute" as a delivery pattern precisely because it leaves a thinner file-based forensic trail — controls built around scanning downloaded files will miss it entirely, and disabling the WebDAV Client service is a disproportionately high-leverage, low-cost mitigation most organizations have not applied. Second, **EtherHiding-style on-chain C2 resolution** (used here at three separate points — OS selection, Amatera's config, and ZigCryptoStealer's C2) is maturing from a novelty into standard tooling; blockchain RPC calls from non-wallet desktop processes are a durable, protocol-level detection opportunity that outlives any specific contract address. Third, **parallel-branch delivery from one entry point** (two independently engineered loader/payload chains sharing only the initial ClickFix lure and the Amatera stealer) shows operators treating the social-engineering front end as reusable infrastructure separate from the payload supply chain — expect the same lure to keep rotating in new payload combinations after this specific report is fully signatured.

## Sources

- [Cisco Talos: ClearFake WebDAV Infection Chain](https://blog.talosintelligence.com/clearfake-webdav-infection-chain/) — primary technical analysis (infection chain, Amatera/ZigCryptoStealer/NetSupport internals, C2 infrastructure, MITRE mapping, attribution)
- [Cisco Talos IOC Repository — clearfake-webdav-infection-chain.txt](https://raw.githubusercontent.com/Cisco-Talos/IOCs/refs/heads/main/2026/09/clearfake-webdav-infection-chain.txt) — full published domain/IP/URL/hash indicator list

---
*Report generated by Actioner*
