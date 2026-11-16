# SANSAR Linux Cryptomining Malware (REF3364) -- Draft Technical Analysis

> **Status**: DRAFT -- Actioner automated analysis
> **Date**: 2026-11-16
> **Analyst**: Actioner (automated)
> **Classification**: TLP:CLEAR

---

## Executive Summary

A financially motivated threat cluster tracked as **REF3364** has been observed operating a Linux cryptomining campaign targeting GPU-equipped hosts through exposed Ray job submission APIs. The operation deploys **SANSAR**, a Rust-based orchestrator that communicates over the TOR network, alongside CPU and GPU miners, an ftrace-based kernel rootkit, a modified NVIDIA Management Library (NVML) wrapper that falsifies GPU telemetry, and an Ethereum-contract-assisted backdoor. Elastic Security Labs published research on this toolkit in November 2026 after observing intrusions on three Linux GPU hosts beginning October 22, 2026.

The campaign is notable for its layered evasion: the NVML wrapper reports GPU utilization as 0%, randomizes temperature and power readings, and filters process listings; while the kernel rootkit hides processes, files, and socket entries from both user-space tools and system calls.

---

## Background

**REF3364** is an activity cluster identified by Elastic Security Labs. Turkish-language comments found in the rootkit source code provide a possible but unconfirmed attribution lead. The group targets organizations running GPU-accelerated workloads with internet-exposed AI/ML job submission infrastructure, specifically the Ray framework.

The toolkit combines:
- Custom malware (SANSAR orchestrator, NVML hook, kernel rootkit, netns backdoor)
- Legitimate miners abused for cryptojacking (XMRig, SRBMiner-MULTI)
- Legitimate privacy tools repurposed for C2 (Tor via Arti and Lyrebird)

---

## Attack Timeline

| Date | Event |
|------|-------|
| **2026-10-22** | External probes appear in Ray job agent logs |
| **2026-10-24** | Submitted Ray job runs `nvidia-smi` to exfiltrate GPU inventory |
| **2026-10-25** | Python reverse-shell job connects to an external listener |
| **2026-10-25+** | SSH key added to `authorized_keys` for persistence |
| **Post-access** | Full toolkit deployed to `/opt/vadi_/` with rootkit, NVML hook, miners, and C2 |
| **2026-11-~09** | Elastic Security Labs publishes research |
| **2026-11-16** | The Hacker News coverage |

---

## Root Cause

The initial access vector was an **unauthenticated, internet-exposed Ray job submission agent**. While the Ray dashboard was bound to loopback, the job agent endpoint was reachable from the internet and accepted unauthenticated job submissions. This allowed the attacker to submit arbitrary Python jobs that ran `nvidia-smi` for reconnaissance and subsequently deployed a reverse shell.

---

## Technical Analysis

### Stage 1: Initial Access and Reconnaissance

The attacker submitted Ray jobs to the exposed agent. The first payload ran:

```
nvidia-smi --query-gpu=name --format=csv,noheader
```

This collected GPU model information for mining profitability assessment. A follow-up job deployed a Python reverse shell connecting to an external listener.

### Stage 2: Persistence Establishment

- **SSH persistence**: An SSH public key was added to the Ray service account's `authorized_keys` file (T1098.004).
- **Root escalation**: After gaining root, the actor staged the full toolkit under `/opt/vadi_/`.

### Stage 3: SANSAR Orchestrator Deployment

**SANSAR** (client version 0.1.3) is a Rust binary that serves as the central C2 client and miner supervisor.

**Anti-analysis features:**
- Reads `/proc/self/status` and exits if `TracerPid` is non-zero (debugger detection)
- Timing check: exits if a 1,000-iteration loop exceeds 501 ms (sandbox detection)
- C2 hostname encoded as 62 bytes using rotation and XOR: `plaintext[i] = ROR8(ciphertext[i], (i % 7) + 1) XOR mask[i % 32]`

**C2 protocol:**
- Connects to `.onion` service via Arti (Rust Tor implementation) with a 60-second bootstrap deadline
- Fallback: Bridge mode through Lyrebird (obfs4/WebTunnel) with 900-second deadline
- Wire format: 4-byte big-endian body length, 4-byte little-endian message type, payload
- Authentication: 40-byte field with BE64 Unix timestamp + HMAC-SHA256(K, client_id || timestamp)

**C2 command types (IDs 0-15):**
RegisterAck (0), HeartbeatAck (1), Command (2), Disconnect (3), BridgeUpdate (4), ShellOpen (5), ShellData (6), ShellResize (7), ShellClose (8), StressStart (9), StressStop (10), MinerStart (11), MinerStop (12), MinerConfigUpdate (13), MinerOutputStart (14), MinerOutputStop (15)

**Shell anti-forensics:** Opens `/bin/bash --norc --noprofile` with `HISTFILE=/dev/null` and history-size variables zeroed.

**Host reconnaissance:** Reads `/etc/hostname`, `/proc/cpuinfo`, `/proc/uptime`, `who`, `/proc/loadavg`, and runs `nvidia-smi`.

### Stage 4: Miner Deployment

| Miner Type ID | Internal Name | Binary | Software |
|---|---|---|---|
| 0 | GpuWildrig | `tilki` | SRBMiner-MULTI v3.6.9 |
| 1 | CpuXmrig | `kurt` | XMRig v6.25.0 |

Miner configuration (pool, wallet, algorithm, extra args, proxy flag) is received from C2. No hardcoded fallback pool or wallet values.

### Stage 5: NVML Library Hooking (GPU Telemetry Evasion)

SANSAR maintains a **modified `libnvidia-ml.so.1`** that wraps the genuine NVIDIA Management Library:

- Installed via `make && make install` using `ldconfig` to locate the NVIDIA library directory
- The genuine library is backed up to `/usr/lib/.libnvidia-ml.so.1.backup`
- Source code stored in `/opt/vadi_/nvml-hook/`

**Hooked behaviors:**
- `nvmlDeviceGetUtilizationRates`: Reports GPU utilization as **0%**
- `nvmlDeviceGetTemperature`: Returns random value between **36-46 C**
- `nvmlDeviceGetPowerUsage`: Returns random value between **100-200 W**
- `nvmlDeviceGetComputeRunningProcesses`: Filters mining process entries

This renders `nvidia-smi` and any NVML-based monitoring tool blind to mining activity.

### Stage 6: Kernel Rootkit (acpi_thermal_mgr.ko)

An ftrace-based kernel rootkit disguised as a thermal management module:

- **Build method**: DKMS (Dynamic Kernel Module Support)
- **Persistence**: Placed in initramfs for boot-time loading
- **Source path**: `/usr/src/acpi_thermal_mgr-1.0/acpi_thermal_mgr.c` (contains Turkish-language comments)

**Hooked syscalls:** `getdents`, `getdents64`, `open`, `openat`, `kill`, `sched_getaffinity`-style PID queries, kernel TCP/UDP socket listing routines.

**Module parameters:**
- `hide_name`: Exempts the process named `sansar` from the `kill` filter
- `hide_prefix`: Hides files/directories by prefix
- `hide_module`: Removes the module from kernel module list and sysfs (disabled by default)
- Watchdog executable paths

**Default hidden processes:** `kurt` and `lyrebird`

**Effects:**
- Removes hidden PIDs from `/proc` directory listings
- Returns `ENOENT` for hidden `/proc/<pid>` paths and hidden filenames
- Returns `ESRCH` for hidden PIDs in `kill` and similar calls
- Hides worker threads even with different names
- Intercepts signals targeting hidden processes

### Stage 7: Netns Ethereum-Assisted Backdoor

A separate binary registered as a **systemd service** that provides an alternative C2 channel:

- Retrieves controller IPv4 address from Ethereum smart contract `0x43eb291f56688c63c93e8a93c4591fc997cf6349` using function selector `0x6ded96e7` via `eth_call` over HTTPS to public Ethereum RPC endpoints
- Connects to the decoded IPv4 address on **TCP port 8080**
- Accepts `SHELL <host> <port>` commands, forking bash to the specified endpoint
- No application-layer authentication or integrity checks

### DDoS Capability

SANSAR includes raw IPv4 TCP SYN flood functionality controlled via `StressStart`/`StressStop` commands, indicating the toolkit may also serve as a DDoS platform.

---

## Indicators of Compromise (IOCs)

### File Hashes (SHA-256)

| File | SHA-256 | Description |
|------|---------|-------------|
| `sansar` | `00c9ac44291f83c72d54302e99d155a3e26d02225a3e516764d5833a99657c9e` | SANSAR orchestrator |
| `kurt` | `96fc528ca5e7d1c2b3add5e31b8797cb126f704976c8fbeaecdbf0aa4309ad46` | XMRig 6.25.0 CPU miner |
| `tilki` | `acc706afc9322a3eae1ef49049749e0a7c9f1a123895ac56dc8a289beb2fb5b7` | SRBMiner-MULTI 3.6.9 GPU miner |
| `lyrebird` | `cc1ad7f14777a098ccc91fd4e8f6143da14418c2b6fdf23b7f8f6b3d1b0b7f1d` | Tor transport helper 0.8.1 |
| `libnvidia-ml.so.1` | `675c24728f87f7aa0fa07527027c95c24c246049c65eaef89270ab04ea50a180` | Modified NVML wrapper |
| `acpi_thermal_mgr.ko` | `6ba1aa275e0e2826e8b48b36473539ca56cbdc41f429e539a45f8532b084d7a4` | Kernel rootkit module |
| `netns` | `df8ab6fd699e6ae90e63e9696bae8f01342708bafc2ed88af414337e4f237194` | Ethereum-assisted backdoor |

### Network Indicators

| Indicator | Type | Description |
|-----------|------|-------------|
| `efxisnqldelyr5ra25oqfrsut54b34g26e7zrsiuupsoekjof2gho2id[.]onion` | TOR C2 | SANSAR C2 hidden service |
| Port `9051` | TCP | SANSAR TOR C2 port |
| Port `8080` | TCP | Netns backdoor communication port |
| `0x43eb291f56688c63c93e8a93c4591fc997cf6349` | ETH Contract | Netns controller address resolver |
| `0x6ded96e7` | ETH Selector | Netns contract function selector |

### IP Discovery Services (used by SANSAR for host fingerprinting)

- `api[.]ipify[.]org`
- `ifconfig[.]me/ip`
- `icanhazip[.]com`
- `checkip[.]amazonaws[.]com`

### File System Indicators

| Path | Description |
|------|-------------|
| `/opt/vadi_/` | Toolkit staging directory |
| `/opt/vadi_/sansar` | SANSAR orchestrator |
| `/opt/vadi_/kurt` | XMRig CPU miner |
| `/opt/vadi_/tilki` | SRBMiner-MULTI GPU miner |
| `/opt/vadi_/lyrebird` | Tor transport proxy |
| `/opt/vadi_/netns` | Ethereum backdoor |
| `/opt/vadi_/nvml-hook/` | NVML hook source directory |
| `/opt/vadi_/nvml-hook/libnvidia-ml.so.1` | Modified NVML library |
| `/usr/lib/.libnvidia-ml.so.1.backup` | Genuine NVML library backup (hidden file) |
| `/usr/src/acpi_thermal_mgr-1.0/acpi_thermal_mgr.c` | Rootkit source code |
| `arti_data/state`, `arti_data/cache` | SANSAR Tor state files |
| `bridges` | Tor bridge configuration |
| `.client_id` | SANSAR client identity file |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Usage in REF3364 |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Exposed Ray job agent exploitation |
| T1059.006 | Python | Python reverse shell via Ray job |
| T1059.004 | Unix Shell | Bash shells, reverse shells |
| T1098.004 | SSH Authorized Keys | Persistence via authorized_keys |
| T1543.002 | Systemd Service | Netns backdoor persistence |
| T1547.006 | Kernel Modules and Extensions | acpi_thermal_mgr rootkit boot loading |
| T1078.003 | Valid Local Accounts | Reuse of service account |
| T1014 | Rootkit | ftrace-based process/file hiding |
| T1622 | Debugger Evasion | TracerPid check, timing check |
| T1027 | Obfuscated Files | Encoded C2 hostname |
| T1140 | Deobfuscate/Decode | Runtime hostname decoding |
| T1690 | Prevent Command History Logging | HISTFILE=/dev/null |
| T1082 | System Information Discovery | GPU/CPU/host enumeration |
| T1016 | Network Configuration Discovery | Public IP discovery |
| T1090.003 | Multi-hop Proxy | TOR C2 via Arti/Lyrebird |
| T1102.001 | Dead Drop Resolver | Ethereum contract for C2 address |
| T1095 | Non-Application Layer Protocol | Custom wire protocol over TOR |
| T1105 | Ingress Tool Transfer | Toolkit staging |
| T1496.001 | Compute Hijacking | CPU and GPU cryptomining |
| T1498.001 | Direct Network Flood | TCP SYN flood capability |

---

## Impact Assessment

- **Financial**: Significant compute and electricity costs from unauthorized GPU/CPU mining across compromised hosts
- **Operational**: GPU workloads degraded despite telemetry showing normal readings; rootkit prevents standard monitoring
- **Security**: Persistent backdoor access via SSH keys, systemd service, initramfs rootkit, and Ethereum-resolved C2 creates multiple re-entry vectors
- **DDoS risk**: The SYN flood capability means compromised hosts could be weaponized for network attacks
- **Detection difficulty**: Multi-layered evasion (NVML hooking + kernel rootkit + TOR C2) makes this substantially harder to detect than typical cryptominers

---

## Detection and Remediation

### Detection Priorities

1. **File integrity monitoring** on NVIDIA libraries -- compare `libnvidia-ml.so.1` hash against vendor packages
2. **Look for hidden backup** at `/usr/lib/.libnvidia-ml.so.1.backup`
3. **Kernel module auditing** -- check for `acpi_thermal_mgr` in loaded modules, DKMS, and initramfs
4. **Process hunting** -- search for `sansar`, `kurt`, `tilki`, `lyrebird`, `netns` processes (note: rootkit may hide these from standard tools; use kernel-level or memory forensics)
5. **Network monitoring** -- TOR connections, Ethereum RPC `eth_call` traffic from server infrastructure
6. **Ray API audit** -- verify job agents are not internet-exposed

### Remediation Steps

1. Isolate affected hosts immediately
2. Rebuild from known-good images (rootkit in initramfs means live remediation is unreliable)
3. Rotate all SSH keys and credentials on affected hosts
4. Restrict Ray job agent binding to loopback/internal networks with authentication
5. Verify NVIDIA library integrity post-rebuild
6. Monitor Ethereum contract `0x43eb291f56688c63c93e8a93c4591fc997cf6349` for new controller IPs
7. Block TOR exit nodes and known bridge addresses at network perimeter

---

## Detection Rules

### Sigma Rule 1: SANSAR Cryptomining Toolkit Component Execution

Detects execution of known SANSAR toolkit binaries from the staging directory or by name.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0; sigma check failed due to MITRE ATT&CK data fetch blocked by proxy (not a rule defect) -->

**Compile status**: compiled (Splunk + LogScale) | **Confidence**: Medium (process name matching can be evaded by renaming)

```yaml
title: SANSAR Cryptomining Toolkit Component Execution
id: 7a3e1f4b-8c2d-4e5a-b6f7-9d0e1c2a3b4c
status: experimental
description: Detects execution of known SANSAR toolkit binaries (sansar, kurt, tilki, lyrebird, netns) associated with REF3364 cryptomining operations.
references:
    - https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware
    - https://thehackernews.com/2026/11/sansar-linux-cryptomining-malware-uses.html
author: Actioner
date: 2026-11-16
tags:
    - attack.t1496.001
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_path:
        Image|contains: '/opt/vadi_/'
    selection_name:
        Image|endswith:
            - '/sansar'
            - '/kurt'
            - '/tilki'
            - '/lyrebird'
            - '/netns'
    condition: selection_path or selection_name
falsepositives:
    - Legitimate use of identically named binaries in custom paths is unlikely but possible
level: high
```

> **Caveat**: The rootkit hides these processes from `/proc`; this rule depends on audit-level or eBPF-based logging that captures execution before rootkit hooks engage.

---

### Sigma Rule 2: NVML Library Backup File Creation

Detects creation of the hidden backup file SANSAR creates before replacing the genuine NVML library.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Compile status**: compiled (Splunk + LogScale) | **Confidence**: High (this specific hidden filename pattern is highly distinctive)

```yaml
title: NVML Library Backup File Creation Indicating GPU Telemetry Hooking
id: 2b4c6d8e-1a3f-5b7c-9d0e-2f4a6c8e0b1d
status: experimental
description: Detects creation of a hidden backup copy of the genuine NVIDIA Management Library, which the SANSAR toolkit creates before replacing it with a hooked wrapper that falsifies GPU utilization readings.
references:
    - https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware
    - https://thehackernews.com/2026/11/sansar-linux-cryptomining-malware-uses.html
author: Actioner
date: 2026-11-16
tags:
    - attack.t1014
    - attack.t1496.001
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains: '.libnvidia-ml.so.1.backup'
    condition: selection
falsepositives:
    - Legitimate NVIDIA driver management scripts creating backups with this exact hidden filename pattern
level: high
```

---

### Sigma Rule 3: acpi_thermal_mgr Kernel Module Activity

Detects loading or DKMS building of the rootkit kernel module.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Compile status**: compiled (Splunk + LogScale) | **Confidence**: High (module name is distinctive and not a legitimate ACPI component)

```yaml
title: Suspicious acpi_thermal_mgr Kernel Module Activity
id: 3c5d7e9f-2b4a-6c8d-0e1f-3a5b7d9e1c2f
status: experimental
description: Detects loading or DKMS building of acpi_thermal_mgr kernel module, used by REF3364 as an ftrace-based rootkit to hide cryptomining processes, files, and network connections.
references:
    - https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware
    - https://thehackernews.com/2026/11/sansar-linux-cryptomining-malware-uses.html
author: Actioner
date: 2026-11-16
tags:
    - attack.t1014
    - attack.t1547.006
logsource:
    category: process_creation
    product: linux
detection:
    selection_insmod:
        Image|endswith:
            - '/insmod'
            - '/modprobe'
        CommandLine|contains: 'acpi_thermal_mgr'
    selection_dkms:
        Image|endswith: '/dkms'
        CommandLine|contains: 'acpi_thermal_mgr'
    condition: selection_insmod or selection_dkms
falsepositives:
    - Legitimate kernel module with the same name is extremely unlikely
level: critical
```

---

### Sigma Rule 4: SANSAR Anti-Forensic Shell Execution

Detects the specific bash invocation pattern used by SANSAR's interactive shell feature.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Compile status**: compiled (Splunk + LogScale) | **Confidence**: Low (behavioral pattern; matches Docker entrypoints, Ansible, CI runners) | **Use**: Informational/correlation only

```yaml
title: SANSAR Anti-Forensic Shell Execution
id: 4d6e8f0a-3c5b-7d9e-1f2a-4b6c8e0f2a3d
status: experimental
description: >
    Detects bash execution with --norc --noprofile flags from non-login-shell parent processes.
    SANSAR uses this pattern when opening interactive C2 shells (it also sets HISTFILE=/dev/null
    via environment variable, which this rule cannot observe). Use as a correlation indicator
    alongside other SANSAR detection rules, not as a standalone alert.
references:
    - https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware
    - https://thehackernews.com/2026/11/sansar-linux-cryptomining-malware-uses.html
author: Actioner
date: 2026-11-16
tags:
    - attack.t1059.004
    - attack.t1690
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/bash'
        CommandLine|contains|all:
            - '--norc'
            - '--noprofile'
    filter_login:
        ParentImage|endswith:
            - '/sshd'
            - '/login'
            - '/su'
    filter_automation:
        ParentImage|endswith:
            - '/docker'
            - '/containerd-shim'
            - '/ansible'
            - '/python'
            - '/jenkins'
    condition: selection and not filter_login and not filter_automation
falsepositives:
    - Docker container entrypoints
    - Ansible playbook execution
    - CI/CD runners and build systems
    - Shell initialization scripts
level: low
```

> **Caveat**: This is a behavioral pattern not unique to SANSAR. The rule detects only the `--norc --noprofile` CLI arguments; it does NOT detect the `HISTFILE=/dev/null` environment variable manipulation. Use only as a correlation indicator alongside other SANSAR artifacts.

---

### Sigma Rule 5: Netns Backdoor Systemd Service Installation

Detects enabling or starting of the netns systemd service used as a persistent backdoor.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Compile status**: compiled (Splunk + LogScale) | **Confidence**: Low (the name "netns" collides with Linux network namespace tooling)

```yaml
title: Netns Backdoor Systemd Service Installation
id: 5e7f9a1b-4d6c-8e0f-2a3b-5c7d9f1a3b4e
status: experimental
description: >
    Detects systemctl commands enabling or starting a netns-related service that references
    the SANSAR staging directory, or direct execution of the netns backdoor binary. The bare
    service name "netns" collides with Linux network namespace tooling; the path-based
    selection anchors detection to the REF3364 toolkit.
references:
    - https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware
    - https://thehackernews.com/2026/11/sansar-linux-cryptomining-malware-uses.html
author: Actioner
date: 2026-11-16
tags:
    - attack.t1543.002
    - attack.t1102.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_systemctl_path:
        Image|endswith: '/systemctl'
        CommandLine|contains:
            - '/opt/vadi_/netns'
    selection_systemctl_service:
        Image|endswith: '/systemctl'
        CommandLine|contains: 'netns.service'
    selection_action:
        CommandLine|contains:
            - 'enable'
            - 'start'
    selection_direct:
        Image|contains: '/opt/vadi_/netns'
    condition: ((selection_systemctl_path or selection_systemctl_service) and selection_action) or selection_direct
falsepositives:
    - Linux network namespace management tools using netns naming (mitigated by path anchoring)
    - Container orchestration platforms managing network namespaces
level: low
```

> **Caveat**: The systemctl-only selections (without the `/opt/vadi_/` path) have high false-positive potential in container/Kubernetes environments. The path-anchored selections are more reliable. Correlate with other SANSAR indicators.

---

### Sigma Rule 6: GPU Reconnaissance via nvidia-smi Query Format

Detects the specific nvidia-smi query pattern used by SANSAR for GPU inventory.

<!-- audit: sigma convert --without-pipeline -t splunk exit 0; sigma convert --without-pipeline -t log_scale exit 0 -->

**Compile status**: compiled (Splunk + LogScale) | **Confidence**: Low (legitimate monitoring uses identical syntax)

```yaml
title: GPU Reconnaissance via nvidia-smi Query Format
id: 6f8a0b2c-5e7d-9f1a-3b4c-6d8e0a2b4c5f
status: experimental
description: Detects nvidia-smi executed with the specific --query-gpu flag and CSV output format used by SANSAR for GPU inventory collection during initial reconnaissance.
references:
    - https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware
    - https://thehackernews.com/2026/11/sansar-linux-cryptomining-malware-uses.html
author: Actioner
date: 2026-11-16
tags:
    - attack.t1082
    - attack.t1496.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/nvidia-smi'
        CommandLine|contains|all:
            - '--query-gpu'
            - '--format=csv'
    condition: selection
falsepositives:
    - Legitimate GPU monitoring and inventory scripts frequently use this syntax
level: low
```

> **Caveat**: This pattern is extremely common in legitimate GPU monitoring; use only as a correlation indicator alongside other SANSAR artifacts.

---

### YARA Rule 1: SANSAR Orchestrator

Detects the SANSAR Rust-based cryptomining orchestrator binary based on embedded strings from its C2 command types, anti-analysis code, and miner management functions.

<!-- audit: yarac exit 0 -->

**Compile status**: compiled (yarac) | **Confidence**: Medium (string-based detection; strings may change between versions)

```yara
rule SANSAR_Orchestrator {
    meta:
        description = "Detects the SANSAR Rust-based cryptomining orchestrator used by REF3364"
        author = "Actioner"
        date = "2026-11-16"
        reference = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware"
        hash = "00c9ac44291f83c72d54302e99d155a3e26d02225a3e516764d5833a99657c9e"
    strings:
        $s1 = "TracerPid" ascii
        $s2 = "/proc/self/status" ascii
        $s3 = "client_id" ascii
        $s4 = "MinerStart" ascii
        $s5 = "MinerStop" ascii
        $s6 = "MinerConfigUpdate" ascii
        $s7 = "ShellOpen" ascii
        $s8 = "ShellData" ascii
        $s9 = "StressStart" ascii
        $s10 = "StressStop" ascii
        $s11 = "BridgeUpdate" ascii
        $s12 = "--norc" ascii
        $s13 = "--noprofile" ascii
        $s14 = "HISTFILE" ascii
        $s15 = "nvidia-smi" ascii
        $s16 = "GpuWildrig" ascii
        $s17 = "CpuXmrig" ascii
        $rust = "rustc" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize < 20MB and
        $rust and
        8 of ($s*)
}
```

---

### YARA Rule 2: SANSAR NVML Hook Library

Detects the modified NVML wrapper library based on the combination of hooked NVML function names and the backup file path string.

<!-- audit: yarac exit 0 -->

**Compile status**: compiled (yarac) | **Confidence**: High (the backup path string combined with NVML hooks is highly specific)

```yara
rule SANSAR_NVML_Hook {
    meta:
        description = "Detects the modified NVML wrapper library used by SANSAR to falsify GPU telemetry"
        author = "Actioner"
        date = "2026-11-16"
        reference = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware"
        hash = "675c24728f87f7aa0fa07527027c95c24c246049c65eaef89270ab04ea50a180"
    strings:
        $nvml1 = "nvmlDeviceGetUtilizationRates" ascii
        $nvml2 = "nvmlDeviceGetTemperature" ascii
        $nvml3 = "nvmlDeviceGetPowerUsage" ascii
        $nvml4 = "nvmlDeviceGetComputeRunningProcesses" ascii
        $backup = ".libnvidia-ml.so.1.backup" ascii
        $hook = "nvml_hook" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        $backup and
        $hook and
        3 of ($nvml*)
}
```

---

### YARA Rule 3: acpi_thermal_mgr Rootkit Module

Detects the ftrace-based kernel rootkit module based on its module parameters and syscall hooking indicators.

<!-- audit: yarac exit 0 -->

**Compile status**: compiled (yarac) | **Confidence**: Medium (parameter name strings may appear in other ftrace-based modules; the combination is distinctive)

```yara
rule SANSAR_Rootkit_acpi_thermal_mgr {
    meta:
        description = "Detects the acpi_thermal_mgr ftrace-based rootkit kernel module used by REF3364"
        author = "Actioner"
        date = "2026-11-16"
        reference = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware"
        hash = "6ba1aa275e0e2826e8b48b36473539ca56cbdc41f429e539a45f8532b084d7a4"
    strings:
        $mod = "acpi_thermal_mgr" ascii
        $ftrace = "ftrace" ascii
        $hide1 = "hide_name" ascii
        $hide2 = "hide_prefix" ascii
        $hide3 = "hide_module" ascii
        $proc = "/proc" ascii
        $getdents = "getdents" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize < 2MB and
        $mod and
        $ftrace and
        $proc and
        2 of ($hide*) and
        $getdents
}
```

---

### YARA Rule 4: Netns Ethereum-Assisted Backdoor

Detects the netns backdoor binary based on the Ethereum contract address and communication patterns.

<!-- audit: yarac exit 0 -->

**Compile status**: compiled (yarac) | **Confidence**: High (the Ethereum contract address is a unique IOC)

```yara
rule SANSAR_Netns_Backdoor {
    meta:
        description = "Detects the netns Ethereum-assisted backdoor used by REF3364"
        author = "Actioner"
        date = "2026-11-16"
        reference = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware"
        hash = "df8ab6fd699e6ae90e63e9696bae8f01342708bafc2ed88af414337e4f237194"
    strings:
        $eth_call = "eth_call" ascii
        $contract = "0x43eb291f56688c63c93e8a93c4591fc997cf6349" ascii nocase
        $selector = "0x6ded96e7" ascii nocase
        $shell_cmd = "SHELL " ascii
        $port = "8080" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        ($contract or $selector) and
        ($eth_call or $shell_cmd) and
        $port
}
```

---

### Suricata Rule 1: Ethereum RPC eth_call to Netns Controller Contract

Detects HTTP traffic containing the Ethereum `eth_call` method targeting the specific contract address used by the netns backdoor.

<!-- audit: suricata -T exit 0 -->

**Compile status**: compiled (suricata -T) | **Confidence**: High (contract address is unique IOC)

```
alert tcp $HOME_NET any -> any any (msg:"SANSAR Ethereum RPC eth_call to Netns Controller Contract"; flow:established,to_server; content:"eth_call"; content:"43eb291f56688c63c93e8a93c4591fc997cf6349"; nocase; distance:0; within:200; reference:url,www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware; classtype:trojan-activity; sid:2026001; rev:1;)
```

---

### Suricata Rule 2: SANSAR Public IP Discovery DNS Lookup

Detects DNS queries to `api.ipify.org`, used by SANSAR as the first service in its public IP discovery chain.

<!-- audit: suricata -T exit 0 -->

**Compile status**: compiled (suricata -T) | **Confidence**: Low (legitimate services commonly query ipify)

```
alert dns $HOME_NET any -> any any (msg:"SANSAR Public IP Discovery Service DNS Lookup"; dns.query; content:"api.ipify.org"; reference:url,www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware; classtype:policy-violation; sid:2026002; rev:1;)
```

> **Caveat**: Use only as a correlation indicator; ipify is widely used by legitimate applications.

---

### Suricata Rule 3: Potential TOR Hidden Service C2 on Port 9051

Detects outbound TCP connections to port 9051, the C2 port used by SANSAR's TOR hidden service.

<!-- audit: suricata -T exit 0 -->

**Compile status**: compiled (suricata -T) | **Confidence**: Low (port 9051 is also used by the Tor control protocol)

```
alert tcp $HOME_NET any -> any 9051 (msg:"SANSAR Potential TOR Hidden Service C2 on Port 9051"; flow:established,to_server; threshold:type limit,track by_src,count 1,seconds 300; reference:url,www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware; classtype:trojan-activity; sid:2026003; rev:1;)
```

> **Caveat**: Port 9051 is the standard Tor control port; this rule is useful only in environments where Tor is not expected.

---

### Suricata Rule 4: Netns Backdoor SHELL Command

Detects the `SHELL ` command prefix at the start of TCP payload on port 8080, matching the netns backdoor's command protocol.

<!-- audit: suricata -T exit 0 -->

**Compile status**: compiled (suricata -T) | **Confidence**: Medium (the "SHELL " prefix at offset 0 is distinctive but could match other protocols)

```
alert tcp $HOME_NET any -> any 8080 (msg:"SANSAR Netns Backdoor SHELL Command"; flow:established,to_server; content:"SHELL "; depth:6; reference:url,www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware; classtype:trojan-activity; sid:2026004; rev:1;)
```

---

## Sources

- [Elastic Security Labs - SANSAR Linux Cryptomining Malware (REF3364)](https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware)
- [The Hacker News - SANSAR Linux Cryptomining Malware Uses Modified NVIDIA Library to Hide GPU Activity](https://thehackernews.com/2026/11/sansar-linux-cryptomining-malware-uses.html)
- [MITRE ATT&CK - T1496.001 Compute Hijacking](https://attack.mitre.org/techniques/T1496/001/)
- [MITRE ATT&CK - T1014 Rootkit](https://attack.mitre.org/techniques/T1014/)
- [MITRE ATT&CK - T1102.001 Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
