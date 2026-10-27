<!-- revision: v1.1 — fixed YARA ARM64 offset (18→16); dropped Suricata SID 2100013 (generic .js on port 8085, excessive FP); fixed Sigma rogue-device logsource to product:fortinet/service:fortimanager and tightened selection_localhost; downgraded Sigma auto-script level critical→high; added backend-pipeline caveats to all Sigma rules; corrected Suricata SID 2100012 audit note re port specificity; added config-dependency notes to remediation items -->
# Technical Analysis Report: PEERSTITCH FortiGate Implant (CVE-2024-47575)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-10-27
Version: 1.1

## Executive Summary

PEERSTITCH is a memory-resident ARM64 implant targeting FortiGate firewalls, uncovered by Palo Alto Networks Unit 42 during investigation of threat cluster CL-STA-0954 (also tracked as UNC5820 by Mandiant). The campaign began in June 2024 with exploitation of CVE-2024-47575 ("FortiJump"), a critical (CVSS 9.8) missing-authentication flaw in FortiManager's FGFM daemon on TCP/541. Through this vulnerability, attackers registered a rogue virtual FortiGate, exfiltrated configuration archives (including credentials and certificates) from 500+ managed firewalls, and subsequently deployed the PEERSTITCH implant via CVE-2025-61624, a FortiOS path traversal in the auto-script engine.

The implant uses ptrace-based process injection to embed itself in two FortiOS daemons (`miglogd` and `iked`), leaving no persistent binary on disk, opening no listening ports, and initiating no outbound connections. It establishes a covert intra-process communication channel using string markers and `/proc/<pid>/mem` cross-writes, enabling tagged VPN sessions to bypass FortiOS validation checks. Anti-forensic measures included killing logging daemons, clearing crash logs, and abusing Apache mod_md for persistent SSH reverse shell access.

## Background: FortiManager and FortiGate Infrastructure

FortiManager is Fortinet's centralized management platform for FortiGate firewalls. It communicates with managed FortiGates over the FGFM (FortiGate-FortiManager) protocol on TCP port 541, enabling configuration push/pull, firmware updates, and device provisioning. A compromise of FortiManager grants access to the full configuration corpus of all managed devices, including reversible credential ciphertext, certificates, private keys, and network topology -- making it an extremely high-value target for sophisticated threat actors.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2024-06-27 12:44:04 | First exploitation: inbound connection from 45[.]32[.]41[.]202 to FortiManager TCP/541; `/tmp/.tm` archive created |
| 2024-06-27 12:44:11 | Exfiltration: outbound to 195[.]85[.]114[.]78:443 (~1.82 MB config archive) |
| 2024-09-22 10:02-10:07 | Rogue device `localhost` (serial FMG-VMTM23017412) registered on FortiManager |
| 2024-09-23 11:31 | Second exfiltration attempt; outbound to 104[.]238[.]141[.]143:443 (~1.82 MB) |
| Post-September 2024 | Sniffer configs pushed to downstream FortiGates; credential brute-forcing from exfiltrated ciphertext |
| Post-September 2024 | PEERSTITCH implant deployed via CVE-2025-61624 path traversal |

## Root Cause: CVE-2024-47575 (FortiJump)

CVE-2024-47575 (Fortinet advisory FG-IR-24-423) is a missing-authentication vulnerability (CWE-306) in FortiManager's `fgfmsd`/`fgfmd` daemon. An unauthenticated remote attacker can execute arbitrary code or commands via specially crafted requests to the FMG-Access management channel on TCP/541. Affected versions span FortiManager 6.2.0 through 7.6.0 and FortiManager Cloud 6.4 through 7.4.4. The flaw was publicly disclosed on October 23, 2024, with exploitation observed in the wild since at least June 27, 2024.

The attackers registered a rogue virtual FortiGate named `localhost` with serial number FMG-VMTM23017412, initially from IP 45[.]32[.]41[.]202, later changed to 198[.]199[.]122[.]22. Upon registration, FortiManager generated a configuration archive (`.tm`) containing running configs for 500+ FortiGates, SQLite databases (`global.db`, `revinfo.db`), serial-to-IP inventories, and reversible credential ciphertext.

## Technical Analysis of the Malicious Payload

### 1. Configuration Exfiltration and Reconnaissance

The initial exploitation yielded a gzip-compressed archive staged at `/tmp/.tm` containing:
- Running configurations for all managed FortiGates
- `global.db` and `revinfo.db` SQLite databases
- Serial-to-public-IP inventory and network topology
- Reversible credential ciphertext and certificates/private keys

Unauthorized sniffer configs were subsequently pushed to downstream FortiGates to capture traffic on ports 3696-3706 (TCP), UDP 69 (TFTP), UDP 1812/1813 (RADIUS), and TCP 389 (LDAP). Administrative and SSL/VPN passwords were brute-forced from the reversible ciphertext.

### 2. Privilege Escalation and Staging (CVE-2025-61624)

CVE-2025-61624 is a path traversal in the FortiOS CLI `system.auto-script` engine that allows an authenticated admin to write arbitrary files as root using traversal objects such as `../../../../setup`. The attacker used this to deploy the PEERSTITCH staging chain.

Scripts downloaded from `hxxp://23[.]240[.]77[.]233:8085/` (also `47[.]18[.]167[.]159`) into `/data2/template/`:

| Downloaded As | Saved As | Description |
|---------------|----------|-------------|
| `pM.js` | (self-deleting) | Prep script |
| `a.js` | `index.js` | Emscripten runtime |
| `a.wasm` | `index.wasm` | WASM module |
| `b.js` | `ipssem.js` | Orchestrator |
| `dd` | `lldprx` | ARM64 injector binary |

The injector was launched as `lldprx` with a `!`-delimited argument string, then unlinked itself after execution and terminated the setup process.

### 3. PEERSTITCH Implant

**Format:** 64-bit Linux ARM64 ELF, C language, statically linked to glibc. Memory-resident with no persistent binary, no listening ports, and no outbound connections.

**Target processes:** `/bin/miglogd` (system logging daemon) and `/bin/iked` (IKE/IPsec VPN service).

**Injection flow:**
1. Locates target PIDs via `/proc/<pid>/cmdline` and reads `/proc/<pid>/maps`
2. Attaches with `ptrace(PTRACE_SEIZE)` and `PTRACE_INTERRUPT`, snapshots registers with `PTRACE_GETREGSET`
3. Builds ARM64 bootstrap calling `mmap` (syscall 0xDE) for 0x4000 bytes of RWX memory
4. Writes 1,344-byte payload through `/proc/<pid>/mem`

**Binary patches applied:**
- NOP instruction (0xAA0003E0) at offsets base+0x106F7B8, base+0x1072E20, and base+0x109A570
- 20-byte trampoline at base+0x135102C

**Covert channel:**
- Hooks scan passing data using `strstr()` for marker `8550` and IP marker `169.254.0.1`
- Extracted tokens (up to 31 bytes) stored in a 16-slot ring buffer at offset +0x0F0
- Forwarding table at +0x400 holds counterpart PID and buffer address
- Tags written cross-process via `/proc/<pid>/mem`
- When `iked` sees a matching tag, it takes an alternate return path that skips FortiOS validations

### 4. C2: Apache mod_md ACME Abuse

The auto-script `../../tmp/apache2/conf/md-acme.conf` configured Apache's mod_md to use an attacker-controlled ACME server at 23[.]240[.]77[.]233:8084. `MDChallengeDns01` was mapped to `/bin/node`, and shell metacharacters in the domain field launched an SSH reverse shell (`-F /tmp/upfile/ssh_config -i`). `MDRenewMode` forced repeated renewal polling, creating a persistent re-execution mechanism.

ACME endpoints observed:
- `hxxp://23[.]240[.]77[.]233:8084/directory`
- `hxxp://23[.]240[.]77[.]233:8084/acme/new-acct`
- `hxxp://23[.]240[.]77[.]233:8084/acme/order/11111`
- `hxxp://23[.]240[.]77[.]233:8084/acme/authz/1`
- `hxxp://23[.]240[.]77[.]233:8084/acme/finalize/61924744/774083503`

### 5. FortiManager Impersonation (FGFM)

The account `FortiGateCloud` pulled full configs from multiple firewalls despite the victim having no FortiCloud tenant. Unit 42 assessed with medium confidence that attackers impersonated FortiManager by either bypassing FGFM authentication with the FortiManager serial (CVE-2024-26009) or reusing exfiltrated trust material. Authentic FortiManager sessions may have been terminated via CVE-2024-26008.

### 6. Anti-Forensics / Evasion Techniques

- `killall -9 miglogd` and `killall -9 syslogd` to halt logging
- `diagnose debug crashlog clear` to remove crash evidence
- Automatic rollback of rogue admin accounts, VPN groups, and auto-script objects
- Decoy text `#0 certs managed by ACME` written over `md-acme.conf`
- Induced tunnel-interface telemetry drops (medium confidence)
- Self-unlinking of the injector binary after execution

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - IPs: `[.]` replacing dots (e.g., `45[.]32[.]41[.]202`)
> - URLs: `hxxp://` prefix (e.g., `hxxp://23[.]240[.]77[.]233:8085/`)

### File System

| Platform | Path / Filename | Hash (SHA-256) | Description |
|----------|-----------------|----------------|-------------|
| FortiOS (ARM64) | `lldprx` | `b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70` | PEERSTITCH ARM64 injector |
| FortiOS | mmap bootstrap header | `829b1cd270b30565739a478441833f49f10a49bd06f0d18cc96c8ae4a0431f11` | ARM64 mmap shellcode bootstrap |
| FortiOS | hook data block (1,280 bytes) | `bd064244dad748cf2a44074bee56f5bfab4a2b18ee944b75d1b3febd4c1fe02a` | Injection payload data |
| FortiOS | `pM.js` | `9c4c4436ff5cdf0d6d68f5108031cbf3708a095cde4ef8c09316af7a7110437e` | Self-deleting prep script |
| FortiOS | `ipssem.js` | `fc1b10c58057ef9f1f9a1e2a3d4a1c89f43b0ead451398c70ed7a6e0312b36ee` | Orchestrator script |
| FortiOS | `index.js` | `f84eea718526706afdf2d1a2774fab76ecb11c18fb61995a37be8249c5e379ab` | Emscripten runtime |
| FortiOS | `index.wasm` | `b7ae166fd49a7ecfe6322a80b8aa56d6aa0825d8f5d106dab2e4fb7d14ce15a8` | WASM module |
| FortiOS | shared secret artifact | `8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92` | Hardcoded shared secret "123456" |
| FortiManager | `/tmp/.tm` or `/var/tmp/.tm` | N/A | Gzip-compressed config exfiltration archive |
| FortiManager | `/fds/data/unreg_devices.txt` | MD5: `9DCFAB171580B52DEAE8703157012674` | Contains rogue device entry |

**Key file paths:**
- `/data2/template/` -- staging directory for implant components
- `../../../../setup` -- path traversal payload (CVE-2025-61624)
- `../../tmp/apache2/conf/md-acme.conf` -- ACME abuse config
- `/tmp/apache2/conf/md-acme.conf` -- resolved path of ACME config

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | 45[.]32[.]41[.]202 | Rogue FortiGate registration, initial exploitation |
| IP | 198[.]199[.]122[.]22 | Rogue FortiGate registration (secondary) |
| IP | 23[.]240[.]77[.]233 | Staging server (ports 8084, 8085), ACME C2, VPN source |
| IP | 47[.]18[.]167[.]159 | Staging server, VPN source |
| IP | 104[.]238[.]141[.]143 | Data exfiltration (port 443) |
| IP | 158[.]247[.]199[.]37 | Outbound connection (denied) |
| IP | 195[.]85[.]114[.]78 | Data exfiltration (port 443) |
| IP | 45[.]32[.]63[.]2 | Fortinet advisory IOC |
| IP | 80[.]66[.]196[.]199 | Fortinet advisory IOC |
| IP | 142[.]93[.]177[.]233 | Fortinet advisory IOC |
| IP | 172[.]232[.]167[.]68 | Third-party reported IOC |
| Serial | FMG-VMTM23017412 | Primary rogue FortiGate serial |
| Serial | FMG-VMTM19008093 | Additional rogue serial (Fortinet advisory) |
| Serial | FGVMEVWG8YMT3R63 | Additional rogue serial (Fortinet advisory) |
| Email | 0qsc137p[at]justdefinition[.]com | Disposable email in `subs.dat` |
| URL | hxxp://23[.]240[.]77[.]233:8085/pM.js | Staging script download |
| URL | hxxp://23[.]240[.]77[.]233:8084/acme/* | Fake ACME server endpoints |

### Behavioral

- Anonymous 16,384-byte `rwxp` memory regions in `/proc/<pid>/maps` for `miglogd` and `iked`
- NOP (0xAA0003E0) at specific offsets in `miglogd` process memory
- `open`/`write` syscalls to `/proc/<pid>/mem` between `miglogd` and `iked`
- Signal 11 (SIGSEGV) in `miglogd`, `iked`, or `syslogd` in crash logs
- `system.auto-script` objects containing `../` path traversal sequences
- Unregistered device additions on FortiManager from unexpected IPs
- `FortiGateCloud` account activity without a configured FortiCloud tenant

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | CVE-2024-47575 exploitation of FortiManager FGFM daemon on TCP/541 |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Path traversal auto-script execution, SSH reverse shell via mod_md |
| T1055.008 | Process Injection: Ptrace System Calls | ptrace-based injection into miglogd and iked processes |
| T1005 | Data from Local System | Exfiltration of FortiManager config archives, credentials, certificates |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP staging server on ports 8084/8085, ACME protocol abuse |
| T1070.001 | Indicator Removal: Clear Linux or Mac System Logs | killall logging daemons, crashlog clear |
| T1040 | Network Sniffing | Sniffer configs pushed to FortiGates for RADIUS/LDAP/TFTP capture |
| T1557 | Adversary-in-the-Middle | FGFM impersonation to pull configs from managed firewalls |
| T1078 | Valid Accounts | Use of brute-forced admin and VPN credentials from exfiltrated ciphertext |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | Exfiltration over port 443 to attacker IPs |

## Impact Assessment

The campaign compromised a centralized FortiManager instance managing 500+ FortiGate firewalls. The exfiltration of the complete configuration corpus -- including reversible credentials, certificates, private keys, and topology data -- represents a catastrophic credential and trust boundary compromise. The PEERSTITCH implant's memory-resident nature, absence of disk artifacts, and use of legitimate FortiOS inter-process communication paths make it extremely difficult to detect with standard host-based tools. The attack effectively subverted the entire management-plane trust model of the affected enterprise network.

## Detection & Remediation

### Immediate Detection

```bash
# Check for anonymous RWX memory regions in FortiOS daemons
cat /proc/$(pidof miglogd)/maps | grep 'rwxp' | grep '00000000 00:00 0'
cat /proc/$(pidof iked)/maps | grep 'rwxp' | grep '00000000 00:00 0'

# Check for crash log evidence
diagnose debug crashlog read | grep -i 'signal 11'

# Check for path traversal in auto-script objects
show full-configuration system auto-script | grep '\.\.\/'

# Check FortiManager logs for rogue device registration
grep -i 'Unregistered device' /log/locallog/elog
grep -i 'FMG-VMTM23017412\|FMG-VMTM19008093\|FGVMEVWG8YMT3R63' /log/locallog/elog

# Check for staging directory
ls -la /data2/template/
ls -la /tmp/apache2/conf/md-acme.conf
```

### Remediation

1. **Isolate:** Immediately disconnect the FortiManager from the network and preserve a forensic copy of the VM image
2. **Patch:** Upgrade FortiManager to fixed versions (7.6.1+, 7.4.5+, 7.2.8+, 7.0.13+, 6.4.15+, 6.2.13+)
3. **Factory Reset:** Deploy a fresh or reinitialized FortiManager from known-clean offline-sourced configurations
4. **Credential Rotation:** Rotate ALL credentials: admin passwords, VPN PSKs, certificates, private keys, TACACS/LDAP/RADIUS secrets, SNMP community strings, routing protocol passwords, wireless keys
5. **Device Audit:** Enumerate all FortiGate devices and alert on any previously unseen device names or serials
6. **Memory Forensics:** Check all managed FortiGates for anonymous RWX regions in miglogd/iked process maps *(config-dependent: requires FortiGate CLI shell access, which may not be available in all deployment models or firmware versions)*

### Long-Term Hardening

1. **Deny unknown devices:** `config system global; set fgfm-deny-unknown enable; end` (FortiManager 7.0.12+/7.2.5+/7.4.3+)
2. **Local-in policies:** Whitelist only known FortiGate IPs for port 541 access
3. **Custom certificates:** Set `fgfm-ca-cert` and enable `fgfm-cert-exclusive` to require a custom CA for FGFM *(config-dependent: requires existing PKI infrastructure with a private CA; not applicable to environments using only Fortinet default certificates)*
4. **Network segmentation:** Restrict management-plane access to dedicated out-of-band management networks
5. **Baseline device inventory:** Implement daily FortiGate device enumeration with alerting on new additions

## Detection Rules

Detection rules cover four planes: host-level binary/memory analysis (YARA), log-based FortiManager/FortiOS event detection (Sigma), and network-level traffic inspection (Suricata, Snort). The memory-resident nature of PEERSTITCH limits host-based detection to binary analysis of the injector and memory forensics; network rules focus on the staging and C2 infrastructure, not the implant's covert FGFM channel which uses legitimate protocol traffic.

### YARA: PEERSTITCH ARM64 Injector

Detects the PEERSTITCH injector binary and staging scripts based on FortiOS-specific strings and ARM64 ELF characteristics.

<!-- audit: compile-status=pass (yarac exit 0). Targets the lldprx injector and staging scripts. Condition requires ELF+ARM64 header plus FortiOS-specific string combinations to minimize FP on general ARM64 binaries. Hash anchored to known sample b9fb0b27. -->

compile: pass | confidence: high

```yara
rule APT_Linux_PEERSTITCH_FortiGate_Implant
{
    meta:
        description = "Detects PEERSTITCH ARM64 injector (lldprx) targeting FortiGate miglogd and iked processes via ptrace-based memory injection"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        hash = "b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $elf = { 7F 45 4C 46 }
        $arm64 = { 02 00 B7 00 }

        $proc_mem = "/proc/%d/mem" ascii
        $proc_maps = "/proc/%d/maps" ascii
        $proc_cmdline = "/proc/%d/cmdline" ascii
        $miglogd = "/bin/miglogd" ascii
        $iked = "/bin/iked" ascii
        $marker_ip = "169.254.0.1" ascii
        $marker_port = "8550" ascii
        $md_acme = "md-acme.conf" ascii
        $cover_string = "certs managed by ACME" ascii

        $mmap_syscall = { D2 80 1B C0 }
        $nop_instr = { E0 03 00 AA }

    condition:
        $elf at 0 and
        $arm64 at 16 and
        filesize < 5MB and
        (
            ($proc_mem and $miglogd and $iked) or
            (4 of ($proc_mem, $proc_maps, $proc_cmdline, $miglogd, $iked, $marker_ip, $marker_port, $md_acme, $cover_string)) or
            ($mmap_syscall and $nop_instr and 2 of ($proc_mem, $miglogd, $iked))
        )
}

rule APT_Linux_PEERSTITCH_Staging_Scripts
{
    meta:
        description = "Detects PEERSTITCH staging scripts (pM.js, ipssem.js) used in the FortiGate implant delivery chain"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        hash = "9c4c4436ff5cdf0d6d68f5108031cbf3708a095cde4ef8c09316af7a7110437e"
        tlp = "WHITE"
        severity = "high"

    strings:
        $lldprx = "lldprx" ascii fullword
        $data2_template = "/data2/template/" ascii
        $index_wasm = "index.wasm" ascii
        $ipssem = "ipssem.js" ascii
        $setup_traversal = "../../../../setup" ascii
        $md_acme_traversal = "../../tmp/apache2/conf/md-acme.conf" ascii
        $pM = "pM.js" ascii

    condition:
        filesize < 1MB and
        (
            ($setup_traversal or $md_acme_traversal) or
            ($lldprx and $data2_template) or
            (3 of ($lldprx, $data2_template, $index_wasm, $ipssem, $pM))
        )
}
```

### Sigma: FortiManager Rogue Device Registration (CVE-2024-47575)

Detects registration of unauthorized devices on FortiManager, including known malicious serial numbers from the PEERSTITCH campaign.

> **Backend pipeline required:** This rule uses `msg|contains` which assumes your SIEM backend maps FortiManager syslog message fields to the `msg` field. A custom pipeline or parser (e.g., FortiManager syslog-to-Sigma field mapping) is required for this rule to fire.

<!-- audit: compile-status=pass (sigma convert --without-pipeline -t splunk exit 0; sigma convert -t log_scale exit 0). Targets FortiManager event logs. Rogue serial match is high-fidelity; generic unregistered-device match may produce FP on legitimate device onboarding. -->

compile: pass | confidence: medium (behavioral) / high (serial-specific)

```yaml
title: FortiManager Rogue Device Registration (CVE-2024-47575)
id: 8a3e7c1f-4b2d-4e9a-b6c8-1d5f0a3e7c9b
status: experimental
description: >
    Detects registration of unauthorized FortiGate devices on FortiManager,
    a key indicator of CVE-2024-47575 (FortiJump) exploitation used in PEERSTITCH campaigns.
    The attacker registers a rogue virtual FortiGate named localhost with a known malicious serial number.
references:
    - https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/
    - https://cloud.google.com/blog/topics/threat-intelligence/fortimanager-zero-day-exploitation-cve-2024-47575
    - https://www.fortiguard.com/psirt/FG-IR-24-423
author: Actioner
date: 2026-10-27
tags:
    - attack.t1190
logsource:
    product: fortinet
    service: fortimanager
detection:
    selection_unregistered:
        msg|contains|all:
            - 'Unregistered device'
            - 'add succeeded'
    selection_serial:
        msg|contains:
            - 'FMG-VMTM23017412'
            - 'FMG-VMTM19008093'
            - 'FGVMEVWG8YMT3R63'
    selection_localhost:
        msg|contains|all:
            - 'Unregistered'
            - 'localhost'
    # Note: selection_serial is high-fidelity (known-bad serials); selection_unregistered
    # and selection_localhost are behavioral and may fire on legitimate device onboarding.
    condition: selection_unregistered or selection_serial or selection_localhost
falsepositives:
    - Legitimate new FortiGate device registrations on FortiManager
level: high
```

### Sigma: FortiOS Auto-Script Path Traversal (CVE-2025-61624)

Detects path traversal sequences in FortiOS auto-script objects used to deploy the PEERSTITCH loader.

> **Backend pipeline required:** This rule uses `msg|contains` which assumes your SIEM backend maps FortiOS CLI audit log fields to the `msg` field. A custom pipeline or parser is required for this rule to fire.

<!-- audit: compile-status=pass (sigma convert --without-pipeline -t splunk exit 0; sigma convert -t log_scale exit 0). Path traversal in auto-script is highly specific to exploitation; extremely low FP rate expected. -->

compile: pass | confidence: medium (behavioral)

```yaml
title: FortiOS Auto-Script Path Traversal (CVE-2025-61624 PEERSTITCH)
id: 2b4e8d1a-5c3f-4a7b-9e6d-0f8a1b2c3d4e
status: experimental
description: >
    Detects FortiOS CLI auto-script objects containing path traversal sequences,
    indicating exploitation of CVE-2025-61624 used to deploy the PEERSTITCH implant.
    Attackers used system.auto-script with traversal paths to write files as root.
references:
    - https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/
author: Actioner
date: 2026-10-27
tags:
    - attack.t1059.004
logsource:
    category: firewall
detection:
    selection_autoscript:
        msg|contains|all:
            - 'auto-script'
            - '../'
    selection_specific_paths:
        msg|contains:
            - '../../../../setup'
            - '../../tmp/apache2/conf/md-acme.conf'
    condition: selection_autoscript or selection_specific_paths
falsepositives:
    - Extremely unlikely in legitimate FortiOS operations
level: high
```

### Sigma: Network Connection to PEERSTITCH C2 Infrastructure

Detects connections to known PEERSTITCH/CL-STA-0954/UNC5820 IP addresses.

> **Backend pipeline required:** This rule uses `dst_ip` which assumes your SIEM backend maps firewall log destination IP fields accordingly. Most Sigma firewall backends handle this natively, but verify your pipeline includes the mapping.

<!-- audit: compile-status=pass (sigma convert --without-pipeline -t splunk exit 0; sigma convert -t log_scale exit 0). IOC-based rule; IPs may be reassigned to legitimate services after infrastructure takedown. Uses real (not defanged) IPs per logsource-encoding spec. -->

compile: pass | confidence: high (IOC-anchored, time-limited)

```yaml
title: Network Connection to PEERSTITCH C2 Infrastructure
id: 7c9e4b2a-3d1f-4e8a-a5b6-9d0c1e2f3a4b
status: experimental
description: >
    Detects network connections to known IP addresses associated with PEERSTITCH / CL-STA-0954 / UNC5820
    infrastructure used for staging, C2, and data exfiltration in the FortiManager CVE-2024-47575 campaign.
references:
    - https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/
    - https://cloud.google.com/blog/topics/threat-intelligence/fortimanager-zero-day-exploitation-cve-2024-47575
    - https://www.fortiguard.com/psirt/FG-IR-24-423
author: Actioner
date: 2026-10-27
tags:
    - attack.t1071.001
logsource:
    category: firewall
detection:
    selection:
        dst_ip:
            - '45.32.41.202'
            - '198.199.122.22'
            - '23.240.77.233'
            - '47.18.167.159'
            - '104.238.141.143'
            - '158.247.199.37'
            - '195.85.114.78'
            - '45.32.63.2'
            - '80.66.196.199'
            - '142.93.177.233'
            - '172.232.167.68'
    condition: selection
falsepositives:
    - Legitimate traffic to shared hosting or VPS providers using these IPs after infrastructure turnover
level: high
```

### Sigma: FortiOS Anti-Forensic Activity

Detects anti-forensic commands observed during the PEERSTITCH campaign.

> **Backend pipeline required:** This rule uses `msg|contains` which assumes your SIEM backend maps FortiOS syslog or CLI audit log fields to the `msg` field. A custom pipeline or parser is required for this rule to fire.

<!-- audit: compile-status=pass (sigma convert --without-pipeline -t splunk exit 0; sigma convert -t log_scale exit 0). Behavioral detection; killall of logging daemons and crashlog clear are uncommon but may occur during authorized maintenance. -->

compile: pass | confidence: medium (behavioral)

```yaml
title: FortiOS Anti-Forensic Activity - Log Daemon Kill and Crashlog Clear
id: 3e5f7a1b-6c4d-4b8e-9a2d-1f0e3c5b7a9d
status: experimental
description: >
    Detects anti-forensic commands observed in the PEERSTITCH campaign, including
    killing logging daemons (miglogd, syslogd) and clearing crash logs on FortiOS devices.
references:
    - https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/
author: Actioner
date: 2026-10-27
tags:
    - attack.t1070.001
logsource:
    category: firewall
detection:
    selection_kill:
        msg|contains:
            - 'killall -9 miglogd'
            - 'killall -9 syslogd'
    selection_crashlog:
        msg|contains: 'diagnose debug crashlog clear'
    condition: selection_kill or selection_crashlog
falsepositives:
    - Authorized FortiOS maintenance operations involving daemon restart
level: high
```

### Suricata: PEERSTITCH Network Detection

Network-level rules for detecting FGFM exploitation traffic, staging server communications, and fake ACME C2.

<!-- revision: dropped Suricata SID 2100013 (generic .js on port 8085) per critic — excessive FP risk -->
<!-- audit: compile-status=pass (suricata -T -S exit 0). SID 2100010 matches known rogue serial in FGFM traffic on TCP/541 (high fidelity). SID 2100012 matches the specific URI /pM.js on any port (no port constraint — relies on URI specificity alone). SID 2100014 targets /acme/ on non-standard port 8084. -->

compile: pass | confidence: high (SID 2100010) / medium (SID 2100012, 2100014)

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 541 (msg:"Actioner - PEERSTITCH Rogue FGFM Connection to FortiManager TCP/541"; flow:established,to_server; content:"FMG-VMTM23017412"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/; metadata:author Actioner, created_at 2026-10-27, cve CVE-2024-47575; sid:2100010; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PEERSTITCH Staging Script Download (pM.js)"; flow:established,to_server; http.uri; content:"/pM.js"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/; metadata:author Actioner, created_at 2026-10-27; sid:2100012; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET 8084 (msg:"Actioner - PEERSTITCH Fake ACME Server Communication Port 8084"; flow:established,to_server; http.uri; content:"/acme/"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/; metadata:author Actioner, created_at 2026-10-27; sid:2100014; rev:1;)
```

### Snort 3: PEERSTITCH Network Detection

Snort 3 rules targeting the same network indicators with Snort-compatible syntax.

<!-- audit: compile-status=pass (snort -c snort.conf -R rules -T exit 0, "Snort successfully validated the configuration!"). SID 2100020 targets rogue serial on FGFM port (high fidelity). SID 2100021-2100022 target staging HTTP (medium fidelity). -->

compile: pass | confidence: high (SID 2100020) / medium (SID 2100021-2100022)

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 541 (msg:"Actioner - PEERSTITCH Rogue FortiGate Serial in FGFM Traffic"; flow:established, to_server; content:"FMG-VMTM23017412"; fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/; metadata:author Actioner, created 2026-10-27, cve CVE-2024-47575; sid:2100020; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - PEERSTITCH Staging Script Download pM.js"; flow:established, to_server; http_uri; content:"/pM.js", fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/; metadata:author Actioner, created 2026-10-27; sid:2100021; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET 8084 (msg:"Actioner - PEERSTITCH Fake ACME Server on Port 8084"; flow:established, to_server; http_uri; content:"/acme/", fast_pattern; classtype:trojan-activity; reference:url,unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/; metadata:author Actioner, created 2026-10-27; sid:2100022; rev:1;)
```

## Lessons Learned

1. **Management platforms are crown jewels.** Compromising a single FortiManager instance granted access to the credentials, configurations, and certificates of 500+ firewalls. Management platforms require the same or greater security controls as the devices they manage, including strict network segmentation, MFA, and continuous monitoring.

2. **Memory-resident implants evade traditional detection.** PEERSTITCH leaves no persistent binary, opens no network connections, and communicates through legitimate inter-process mechanisms. Detection requires memory forensics (checking `/proc/<pid>/maps` for anomalous RWX regions) rather than traditional file-based scanning.

3. **Trust material must be treated as compromised after platform compromise.** The reversible credential ciphertext and certificates exfiltrated from FortiManager enabled credential brute-forcing and potential FortiManager impersonation. Rotating all downstream credentials -- not just admin passwords -- is essential remediation.

4. **Proprietary protocol abuse is a blind spot.** The FGFM protocol on TCP/541 is not widely inspected by third-party security tools, and the attackers' abuse of it for device registration and configuration theft would not appear in standard network monitoring. Organizations should baseline FGFM traffic patterns and alert on anomalies.

## Sources

- [Unit 42 - PEERSTITCH: A Stealthy FortiGate Implant](https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/) -- Primary technical analysis with IOCs, YARA rules, and full implant reverse engineering
- [Mandiant/Google Cloud - FortiManager Zero-Day Exploitation (CVE-2024-47575)](https://cloud.google.com/blog/topics/threat-intelligence/fortimanager-zero-day-exploitation-cve-2024-47575) -- Initial UNC5820 tracking, early exploitation timeline, and forensic indicators
- [Fortinet PSIRT Advisory FG-IR-24-423](https://www.fortiguard.com/psirt/FG-IR-24-423) -- Official advisory with affected/fixed versions, workarounds, and IOCs
- [Rewterz Threat Advisory - PEERSTITCH Active IOCs](https://rewterz.com/threat-advisory/threat-actors-deploy-peerstitch-malware-against-fortinet-firewalls-active-iocs) -- Aggregated IOC list
- [The Hacker News - PEERSTITCH Malware via FortiOS Flaw](https://thehackernews.com/2026/10/attackers-exploit-fortios-flaw-to.html) -- Secondary analysis and coverage
- [Picus Security - CVE-2024-47575 Explained](https://picussecurity.com/resource/blog/cve-2024-47575-fortimanager-missing-authentication-zero-day-vulnerability-explained) -- Vulnerability context and affected version details
- [CSA Singapore Alert AL-2024-134](https://www.csa.gov.sg/alerts-advisories/alerts/2024/al-2024-134) -- Government advisory on CVE-2024-47575 exploitation

---
*Report generated by Actioner*
