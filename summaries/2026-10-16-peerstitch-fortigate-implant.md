# PEERSTITCH: Memory-Resident ARM64 Implant Targeting FortiGate Firewalls

**Date:** 2026-10-16
**Status:** DRAFT
**Author:** Actioner
**Threat Actor Cluster:** CL-STA-0954 / UNC5820
**Malware Family:** PEERSTITCH
**Target Platform:** FortiOS (ARM64 Linux)

---

## Executive Summary

PEERSTITCH is a stealthy, memory-resident ARM64 malware implant targeting FortiGate firewalls, discovered by Palo Alto Networks Unit 42. The implant was deployed through a multi-stage intrusion chain beginning with the exploitation of **CVE-2024-47575** (FortiJump) on FortiManager appliances, followed by exploitation of **CVE-2025-61624** (FortiOS CLI path traversal) on managed FortiGate devices. The campaign, tracked as **CL-STA-0954** (also known as **UNC5820**), compromised a telecommunications managed service provider, exfiltrating configuration archives covering **more than 500 managed FortiGate firewalls**, including reversibly encrypted credentials, certificates, private keys, routing tables, and topology data.

PEERSTITCH is notable for its complete absence of persistent on-disk artifacts, listening sockets, or outbound connections. It operates entirely within memory, injecting code into two FortiOS daemons (`miglogd` and `iked`) via ptrace to create a covert inter-process communication bridge that can bypass FortiOS security validation for VPN sessions.

## Sources

- [Unit 42 Technical Analysis (PRIMARY)](https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/)
- [The Hacker News Coverage](https://thehackernews.com/2026/10/attackers-exploit-fortios-flaw-to.html)
- [Security Affairs Coverage](https://securityaffairs.com/201077/malware/peerstitch-malware-how-attackers-compromised-500-firewalls-through-fortimanager.html)

---

## Attack Chain

### Phase 1: Initial Access via CVE-2024-47575 (FortiJump)

The attackers exploited **CVE-2024-47575**, an unauthenticated remote command execution vulnerability in the FortiManager FMG-Access protocol (TCP 541). They registered a rogue Virtual FortiGate named "**localhost**" with serial number **FMG-VMTM23017412** from the IP addresses `45[.]32[.]41[.]202` (later changed to `198[.]199[.]122[.]22`). Immediately after registration, they exfiltrated a `.tm` configuration archive containing:

- Running configurations for **500+ managed FortiGate firewalls**
- FortiManager serial number and management relationships
- Central management SQLite databases (`global.db`, `revinfo.db`)
- Serial number-to-public IP inventory for all managed devices
- Internal topology maps, routing tables, and interface configurations
- Reversibly encrypted admin, local, and SSL/VPN credentials
- Certificates and private keys

Fortinet Threat Prevention signatures **95788** and **96788** cover this exploitation.

### Phase 2: Reconnaissance and Credential Exploitation

Using the stolen configuration data, the attackers:
- Decrypted stored credentials (reversible ciphertext)
- Established unauthorized SSL/VPN sessions into internal management segments
- Impersonated FortiManager to pull configurations from additional managed firewalls
- Deployed network sniffers targeting TCP 3696-3706, UDP 69 (TFTP), UDP 1812/1813 (RADIUS), TCP 389 (LDAP), and unencrypted HTTP

### Phase 3: PEERSTITCH Deployment via CVE-2025-61624

The PEERSTITCH implant was deployed by exploiting **CVE-2025-61624** (CVSS 5.4), a path traversal flaw in the FortiOS CLI auto-script engine. The attackers used path-traversal auto-script objects (e.g., `../../../../setup` and `../../tmp/apache2/conf/md-acme.conf`) to stage files in `/data2/template/`. Components were downloaded from staging servers over HTTP port 8085.

### Phase 4: PEERSTITCH Execution

The deployment orchestrator (`ipssem.js`) launches the core injector (`lldprx`) with the command line:
```
lldprx!index.js!index.wasm!ipssem.js!lldprx!yyyy!pM.js
```

Anti-forensic measures are executed immediately:
```
killall -9 miglogd
killall -9 syslogd
diagnose debug crashlog clear
```

### Phase 5: Persistent Access via ACME Channel

The attackers abused the native Apache **mod_md** module on FortiGates, embedding shell commands in the domain name field of DNS-01 certificate validation requests. With `MDRenewMode` configured to retry, this created a persistent reverse shell channel. The SSH reverse shell connects to `23[.]240[.]77[.]233:8084` using `/tmp/upfile/ssh_config`.

---

## PEERSTITCH Technical Analysis

### Architecture

PEERSTITCH is a 64-bit ARM64 ELF binary written in C. It is a fileless, memory-resident implant that:
- Leaves **no persistent binary on disk** (self-deletes after execution)
- Opens **no listening sockets**
- Makes **no outbound connections** of its own
- Operates entirely by hooking existing FortiOS daemon processes

### Components

| Component | Original Name | Deployed Name | SHA-256 |
|---|---|---|---|
| Ptrace Injector | dd | lldprx | `b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70` |
| Shellcode Bootstrap (45 bytes) | - | - | `829b1cd270b30565739a478441833f49f10a49bd06f0d18cc96c8ae4a0431f11` |
| Hook Injection Data Block (1,280 bytes) | - | - | `bd064244dad748cf2a44074bee56f5bfab4a2b18ee944b75d1b3febd4c1fe02a` |
| Staging Script | pM.js | pM.js | `9c4c4436ff5cdf0d6d68f5108031cbf3708a095cde4ef8c09316af7a7110437e` |
| Orchestrator | b.js | ipssem.js | `fc1b10c58057ef9f1f9a1e2a3d4a1c89f43b0ead451398c70ed7a6e0312b36ee` |
| Emscripten JS Runtime | a.js | index.js | `f84eea718526706afdf2d1a2774fab76ecb11c18fb61995a37be8249c5e379ab` |
| WASM Module | a.wasm | index.wasm | `b7ae166fd49a7ecfe6322a80b8aa56d6aa0825d8f5d106dab2e4fb7d14ce15a8` |
| Hard-coded Shared Secret ("123456") | - | - | `8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92` |

### Injection Mechanism

The `lldprx` injector targets two FortiOS daemons:
- **`/bin/miglogd`** -- the logging daemon
- **`/bin/iked`** -- the IKE/IPsec VPN daemon

The injection process:

1. Locates target PIDs by scanning `/proc/<pid>/cmdline`
2. Enumerates memory layout via `/proc/<pid>/maps`
3. Attaches via `ptrace(PTRACE_SEIZE)` and halts with `PTRACE_INTERRUPT`
4. Captures register state via `PTRACE_GETREGSET` (X0-X30, SP, PC)
5. Allocates a **16,384-byte RWX memory region** via `mmap` (syscall `0xDE`)
6. Writes a **1,344-byte payload** through `/proc/<pid>/mem`
7. Patches three code locations with ARM64 NOP instructions (`0xAA0003E0` = `MOV X0, X0`) at:
   - `base + 0x106F7B8`
   - `base + 0x1072E20`
   - `base + 0x109A570`
8. Writes a **20-byte trampoline** at `base + 0x135102C`
9. Sets up an ADRP return path for hook branching when a tag is present

### Covert Communication Bridge

The injected hooks create a covert IPC channel between `miglogd` and `iked`:

1. The **miglogd hook** passively inspects network traffic flowing through the logging daemon
2. It searches for two markers using `strstr()`:
   - TCP port string **"8550"** (not an actual listening port)
   - IP string **"169.254.0.1"** (link-local marker, not a real endpoint)
3. When both markers match, `miglogd` extracts a **session tag** (up to 31 bytes) and writes it into `iked`'s memory through `/proc/<pid>/mem`
4. The **iked hook** checks incoming VPN sessions for this tag
5. If a session's injection buffer carries the matching tag, iked **skips default FortiOS security validation**, allowing unauthorized VPN access

Cross-process data structures:
- **16-slot ring buffer** at offset `+0x0F0`
- **Forwarding table** at offset `+0x400`

### Evasion

- No files persist on disk (injector self-deletes)
- No listening sockets or outbound connections from the implant itself
- Fortinet's Integrity Checker Tool cannot detect it (scans disk files only; memory is untouched)
- Kills `syslogd` and `miglogd` to prevent logging
- Clears crash logs
- Rogue admin accounts and auto-script objects deleted after execution
- ACME configuration file overwritten with innocuous text (`#0 certs managed by ACME`)

---

## Indicators of Compromise

### File Hashes (SHA-256)

| Hash | Component |
|---|---|
| `b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70` | lldprx (ARM64 ptrace injector) |
| `829b1cd270b30565739a478441833f49f10a49bd06f0d18cc96c8ae4a0431f11` | Shellcode bootstrap header (45 bytes) |
| `bd064244dad748cf2a44074bee56f5bfab4a2b18ee944b75d1b3febd4c1fe02a` | Core hook injection data block (1,280 bytes) |
| `9c4c4436ff5cdf0d6d68f5108031cbf3708a095cde4ef8c09316af7a7110437e` | pM.js (staging script) |
| `fc1b10c58057ef9f1f9a1e2a3d4a1c89f43b0ead451398c70ed7a6e0312b36ee` | ipssem.js (orchestrator) |
| `f84eea718526706afdf2d1a2774fab76ecb11c18fb61995a37be8249c5e379ab` | index.js (Emscripten JS runtime) |
| `b7ae166fd49a7ecfe6322a80b8aa56d6aa0825d8f5d106dab2e4fb7d14ce15a8` | index.wasm (WASM module) |
| `8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92` | Hard-coded shared secret artifact ("123456") |

### Network Indicators (Defanged)

| Indicator | Role | Ports |
|---|---|---|
| `23[.]240[.]77[.]233` | Staging/payload server, rogue ACME CA, SSH reverse shell target | 8084, 8085 |
| `47[.]18[.]167[.]159` | Staging/payload server | 8085 |
| `45[.]32[.]41[.]202` | Rogue FortiGate registration source (initial) | 541 |
| `198[.]199[.]122[.]22` | Rogue FortiGate registration source (replacement) | 541 |

### File System Indicators

| Path | Purpose |
|---|---|
| `/data2/template/` | Staging directory for downloaded components |
| `/data2/template/lldprx` | Deployed injector binary |
| `/data2/template/index.js` | Emscripten JS runtime |
| `/data2/template/index.wasm` | WASM module |
| `/data2/template/ipssem.js` | Deployment orchestrator |
| `/data2/template/pM.js` | Environment preparation script |
| `/tmp/upfile/ssh_config` | SSH configuration for reverse shell |
| `/tmp/apache2/conf/md-acme.conf` | ACME configuration (overwritten) |
| `../../../../setup` | Path-traversal auto-script object |
| `../../tmp/apache2/conf/md-acme.conf` | Path-traversal auto-script object |

### Process Indicators

| Process | Context |
|---|---|
| `/bin/miglogd` | Injection target (FortiOS logging daemon) |
| `/bin/iked` | Injection target (IKE/IPsec VPN daemon) |
| `/bin/node` | Mapped to MDChallengeDns01 handler for command execution |
| `lldprx` | PEERSTITCH core injector binary |
| `syslogd` | Killed by attackers to suppress logging |

### ACME Endpoint Paths

| Path | Purpose |
|---|---|
| `/directory` | ACME directory discovery |
| `/acme/new-acct` | Account creation |
| `/acme/order/11111` | Certificate order |
| `/acme/authz/1` | Authorization |
| `/acme/finalize/61924744/774083503` | Order finalization |

### Memory Forensic Indicators

- Anonymous `rwxp` memory regions of exactly **16,384 bytes** (0x4000) in `miglogd` or `iked`
- NOP patches (`0xAA0003E0`) at offsets `0x106F7B8`, `0x1072E20`, `0x109A570` relative to process base
- 20-byte trampoline at offset `0x135102C` relative to process base
- Cross-PID `/proc/<pid>/mem` writes
- Signal 11 (SIGSEGV) entries in crash logs

### Rogue Device Indicators

| Indicator | Value |
|---|---|
| Rogue FortiGate Name | localhost |
| Rogue FortiGate Serial | FMG-VMTM23017412 |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Context |
|---|---|---|
| T1190 | Exploit Public-Facing Application | CVE-2024-47575 exploitation of FortiManager FMG-Access (TCP 541) |
| T1133 | External Remote Services | Unauthorized SSL/VPN access using stolen credentials |
| T1055.008 | Process Injection: Ptrace System Calls | lldprx uses ptrace to inject into miglogd and iked |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell commands via SSH reverse shell and mod_md ACME channel |
| T1105 | Ingress Tool Transfer | Component download from staging servers on port 8085 |
| T1071.001 | Application Layer Protocol: Web Protocols | ACME protocol abuse over HTTP for C2; FGFM impersonation |
| T1040 | Network Sniffing | Passive traffic inspection by miglogd hook; deployed sniffers on TFTP/RADIUS/LDAP |
| T1070.004 | Indicator Removal: File Deletion | Self-deleting injector; removal of rogue accounts and auto-scripts |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Killing syslogd and miglogd; clearing crash logs |
| T1556 | Modify Authentication Process | iked hook bypasses FortiOS VPN security validation |
| T1552.001 | Unsecured Credentials: Credentials In Files | Extraction of reversibly encrypted credentials from FortiGate configs |
| T1078 | Valid Accounts | Reuse of decrypted SSL/VPN credentials |
| T1005 | Data from Local System | Exfiltration of configuration archive, databases, topology data |

---

## Detection Rules

### YARA Rules

**File:** `/tmp/actioner/peerstitch_fortigate_implant.yar`

#### Rule 1: `peerstitch_fortigate_arm64_implant`

Detects the PEERSTITCH ARM64 injector binary and memory-resident implant through a combination of ARM64 shellcode patterns and operational strings specific to the FortiGate targeting.

```yara
rule peerstitch_fortigate_arm64_implant {
    meta:
        description = "Detects PEERSTITCH ARM64 memory-resident implant targeting FortiGate firewalls via ptrace injection into miglogd and iked"
        author = "Actioner"
        date = "2026-10-16"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        hash1 = "b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70"
        hash2 = "829b1cd270b30565739a478441833f49f10a49bd06f0d18cc96c8ae4a0431f11"
        hash3 = "bd064244dad748cf2a44074bee56f5bfab4a2b18ee944b75d1b3febd4c1fe02a"

    strings:
        $elf = { 7F 45 4C 46 }
        $mmap_sc = { C8 1B 80 D2 01 00 00 D4 }
        $nop_patch = { E0 03 00 AA }
        $prologue = { FF 43 04 D1 }
        $br_x0 = { 00 00 1F D6 }
        $s_miglogd = "/bin/miglogd" ascii
        $s_iked = "/bin/iked" ascii
        $s_link_local = "169.254.0.1" ascii
        $s_acme_conf = "/tmp/apache2/conf/md-acme.conf" ascii
        $s_acme_managed = "#0 certs managed by ACME" ascii
        $s_proc_mem = "/proc/%d/mem" ascii
        $s_proc_maps = "/proc/%d/maps" ascii
        $s_proc_cmdline = "/proc/%d/cmdline" ascii
        $s_port_marker = "8550" ascii
        $s_ssh_config = "/tmp/upfile/ssh_config" ascii

    condition:
        $elf at 0 and
        (
            ($mmap_sc and $br_x0) or
            ($prologue and $nop_patch) or
            (4 of ($s_*))
        )
}
```

- **Compile status:** PASS (yarac validation successful)
- **Confidence:** HIGH -- based on unique operational strings and ARM64 shellcode patterns directly from Unit 42 analysis

#### Rule 2: `peerstitch_staging_scripts`

Detects PEERSTITCH staging and orchestrator JavaScript components.

```yara
rule peerstitch_staging_scripts {
    meta:
        description = "Detects PEERSTITCH staging and orchestrator JavaScript components used in FortiGate implant deployment"
        author = "Actioner"
        date = "2026-10-16"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        hash_pm = "9c4c4436ff5cdf0d6d68f5108031cbf3708a095cde4ef8c09316af7a7110437e"
        hash_ipssem = "fc1b10c58057ef9f1f9a1e2a3d4a1c89f43b0ead451398c70ed7a6e0312b36ee"

    strings:
        $s1 = "lldprx" ascii
        $s2 = "ipssem" ascii
        $s3 = "index.wasm" ascii
        $s4 = "/data2/template/" ascii
        $s5 = "killall -9 miglogd" ascii
        $s6 = "killall -9 syslogd" ascii
        $s7 = "diagnose debug crashlog clear" ascii
        $s8 = "../../../../setup" ascii

    condition:
        3 of them
}
```

- **Compile status:** PASS (yarac validation successful)
- **Confidence:** HIGH -- unique combination of FortiOS-specific commands and PEERSTITCH component names

### Sigma Rules

#### Rule 1: PEERSTITCH Ptrace Injection Into FortiOS Daemons

**File:** `/tmp/actioner/peerstitch_ptrace_injection.yml`

```yaml
title: PEERSTITCH Ptrace Injection Into FortiOS Daemons
id: 3a7c91e2-f8d4-4b1a-ae29-6c5d0f3e8b17
status: experimental
description: Detects the PEERSTITCH implant injector (lldprx) using ptrace to attach to FortiOS miglogd or iked daemons
references:
    - https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/
author: Actioner
date: 2026/10/16
tags:
    - attack.t1055.008
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_injector:
        Image|endswith: '/lldprx'
    selection_cmdline:
        CommandLine|contains:
            - 'lldprx!index.js!index.wasm!ipssem.js'
            - 'lldprx!yyyy!pM.js'
    condition: selection_injector or selection_cmdline
falsepositives:
    - Unknown
level: critical
```

- **Compile status:** PASS (sigma check: 0 errors, 0 issues; convert to Splunk and LogScale successful)
- **Confidence:** HIGH

#### Rule 2: PEERSTITCH Anti-Forensics Activity on FortiOS

**File:** `/tmp/actioner/peerstitch_antiforensics.yml`

```yaml
title: PEERSTITCH Anti-Forensics Activity on FortiOS
id: 8b2e47f1-c3a6-4d9e-b5f8-1a9d0e7c6f34
status: experimental
description: Detects anti-forensic commands associated with PEERSTITCH deployment
references:
    - https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/
author: Actioner
date: 2026/10/16
tags:
    - attack.t1070.004
    - attack.t1562.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_kill_miglogd:
        CommandLine|contains: 'killall -9 miglogd'
    selection_kill_syslogd:
        CommandLine|contains: 'killall -9 syslogd'
    selection_crashlog:
        CommandLine|contains: 'diagnose debug crashlog clear'
    condition: 1 of selection_*
falsepositives:
    - Legitimate FortiOS maintenance operations
level: high
```

- **Compile status:** PASS (sigma check: 0 errors, 0 issues; convert to Splunk and LogScale successful)
- **Confidence:** HIGH

#### Rule 3: PEERSTITCH Staging Directory and Path Traversal

**File:** `/tmp/actioner/peerstitch_staging_directory.yml`

```yaml
title: PEERSTITCH Staging Directory and Path Traversal Auto-Script
id: d4f19a83-e2b7-4c6f-9317-5b8a0d2e1f69
status: experimental
description: Detects file creation in PEERSTITCH staging directory or path traversal auto-script objects
references:
    - https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/
author: Actioner
date: 2026/10/16
tags:
    - attack.t1190
    - attack.t1105
logsource:
    category: file_event
    product: linux
detection:
    selection_staging:
        TargetFilename|contains:
            - '/data2/template/lldprx'
            - '/data2/template/index.js'
            - '/data2/template/index.wasm'
            - '/data2/template/ipssem.js'
            - '/data2/template/pM.js'
    selection_traversal:
        TargetFilename|contains:
            - '../../../../setup'
            - '../../tmp/apache2/conf/md-acme.conf'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: critical
```

- **Compile status:** PASS (sigma check: 0 errors, 0 issues; convert to Splunk and LogScale successful)
- **Confidence:** HIGH

#### Rule 4: PEERSTITCH C2 Infrastructure Network Connection

**File:** `/tmp/actioner/peerstitch_network_c2.yml`

```yaml
title: PEERSTITCH C2 Infrastructure Network Connection
id: a1c8e5f2-7b3d-4a96-8e1f-9d2c0b5a3e78
status: experimental
description: Detects network connections to known PEERSTITCH C2 and staging infrastructure
references:
    - https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/
author: Actioner
date: 2026/10/16
tags:
    - attack.t1071.001
    - attack.t1105
logsource:
    category: network_connection
    product: linux
detection:
    selection_staging:
        DestinationIp:
            - '23.240.77.233'
            - '47.18.167.159'
        DestinationPort:
            - 8084
            - 8085
    selection_rogue_fgt:
        SourceIp:
            - '45.32.41.202'
            - '198.199.122.22'
        DestinationPort: 541
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: critical
```

- **Compile status:** PASS (sigma check: 0 errors, 0 issues; convert to Splunk and LogScale successful)
- **Confidence:** HIGH

### Snort/Suricata Rules

**File:** `/tmp/actioner/peerstitch_network.rules`

8 rules covering:
- SID 2026101601: Connection to primary staging server `23[.]240[.]77[.]233:8085`
- SID 2026101602: Connection to secondary staging server `47[.]18[.]167[.]159:8085`
- SID 2026101603: Connection to rogue ACME CA `23[.]240[.]77[.]233:8084`
- SID 2026101604: ACME directory request to rogue CA
- SID 2026101605: PEERSTITCH-specific ACME finalize order pattern
- SID 2026101606: Rogue FortiGate registration from `45[.]32[.]41[.]202` on TCP 541
- SID 2026101607: Rogue FortiGate registration from `198[.]199[.]122[.]22` on TCP 541
- SID 2026101608: HTTP download of `pM.js` staging component

- **Compile status:** NOT VALIDATED (Snort/Suricata not available in environment; syntax manually verified)
- **Confidence:** HIGH

---

## Hunting Guidance

### Memory Forensics
- Search for **anonymous `rwxp` 16 KB memory regions** in `miglogd` or `iked` processes
- Verify NOP patches at the three documented offsets relative to process base address
- Look for cross-PID `/proc/<pid>/mem` writes between unrelated processes
- Check crash logs for **Signal 11 (SIGSEGV)** entries in `miglogd` or `iked`

### FortiManager Audit
- Search for auto-script objects containing path traversal sequences (`../`)
- Look for rogue device registrations with serial **FMG-VMTM23017412** or name "localhost"
- Audit FGFM connections (TCP 541) from unexpected source IPs
- Review `.tm` archive exports for unauthorized access

### Network
- Monitor for HTTP traffic on ports **8084** and **8085** to/from the documented infrastructure IPs
- Alert on ACME protocol requests to non-standard ports or unknown CAs
- Watch for SSH connections using custom configuration files from `/tmp/upfile/`

### FortiGate Device
- Fortinet's Integrity Checker Tool will **NOT** detect PEERSTITCH (disk-only scanning)
- Credential rotation is required for all devices whose configs were in the exfiltrated archive
- Certificate and private key material must be revoked and reissued

---

## Vulnerabilities Referenced

| CVE | Product | Description | CVSS |
|---|---|---|---|
| CVE-2024-47575 | FortiManager | Unauthenticated RCE via FMG-Access (FortiJump) | Critical |
| CVE-2025-61624 | FortiOS / FortiPAM / FortiProxy / FortiSwitchManager | CLI path traversal (write/delete arbitrary files) | 5.4 |
| CVE-2024-26009 | FortiOS | Suspected exploitation (unconfirmed; requires FortiCloud SSO) | - |
| CVE-2024-26008 | FortiOS | Suspected exploitation (unconfirmed; requires FortiCloud SSO) | - |

---

## Timeline

| Date | Event |
|---|---|
| September 2024 | Initial intrusion via CVE-2024-47575 on FortiManager |
| September 2024+ | Reconnaissance, credential decryption, SSL/VPN re-entry |
| Post-September 2024 | Network sniffing, FortiManager impersonation, lateral movement |
| Unknown (post-April 2026) | CVE-2025-61624 exploitation and PEERSTITCH deployment |
| October 14, 2026 | Unit 42 report published |

---

## Recommendations

1. **Patch immediately**: Apply updates for CVE-2024-47575 and CVE-2025-61624
2. **Rotate all credentials**: Patching does not invalidate stolen credentials and keys
3. **Revoke certificates**: All certificates and private keys from the exfiltrated archive must be reissued
4. **Memory forensics**: Disk-based integrity checking (including Fortinet's tool) cannot detect PEERSTITCH; memory analysis of `miglogd` and `iked` processes is required
5. **Monitor FGFM (TCP 541)**: Alert on connections from unauthorized source IPs
6. **Audit auto-scripts**: Search for path traversal sequences in FortiManager auto-script objects
7. **Review ACME configuration**: Check Apache `mod_md` settings for embedded commands
8. **Deploy network detection**: Implement the provided Snort/Suricata rules for staging infrastructure
9. **Deploy endpoint detection**: Implement YARA rules for scanning FortiGate firmware images and memory dumps
