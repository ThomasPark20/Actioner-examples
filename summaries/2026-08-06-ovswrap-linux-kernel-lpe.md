# Technical Analysis Report: OVSwrap (CVE-2026-64531) Linux Kernel Local Privilege Escalation

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-06
Version: 1.0 (DRAFT)

## Executive Summary

CVE-2026-64531 ("OVSwrap") is a critical local privilege escalation vulnerability in the Linux kernel's Open vSwitch (OVS) datapath module (`openvswitch.ko`). Discovered by security researcher Asim Manizada and publicly disclosed on July 28, 2026, the flaw allows any unprivileged local user to gain root access on most default-configured Linux distributions. The vulnerability is a 13-year-old integer wraparound bug in Netlink attribute length handling, exposed by a March 2025 kernel change that removed a 32 KiB cap on generated action streams. With a CVSS score of 7.8 and a public proof-of-concept featuring ~800 pre-built kernel records, OVSwrap represents an immediate, high-reliability threat to unpatched Linux systems across enterprise, cloud, and development environments.

The exploit achieves "logic-bug-grade reliability" -- it requires no heap grooming, no race conditions, and deterministically corrupts kernel credentials to inject passwordless sudo rules or open a root shell. Affected distributions include AlmaLinux, Alpine, Amazon Linux 2023, Arch, CentOS Stream, Debian 12/13, Fedora 42-44, Kali, Linux Mint, NixOS, openSUSE Tumbleweed, Pop!_OS, Rocky Linux, and Ubuntu 22.04/24.04/26.04.

## Background: Linux Kernel Open vSwitch Datapath

Open vSwitch (OVS) is a production-quality, multilayer virtual switch widely used in virtualization, SDN, and container networking. The OVS datapath operates as a Linux kernel module (`openvswitch.ko`) that handles fast-path packet forwarding. Critically, the module is shipped as a loadable kernel module on nearly all major distributions and can be auto-loaded by any process that resolves its Generic Netlink family name -- including processes running inside unprivileged user namespaces.

The kernel datapath accepts flow action lists from userspace via Netlink and rewrites certain actions into larger internal representations stored as `sw_flow_actions`. Individual actions are encoded as Netlink attributes using a 16-bit `nla_len` field, limiting each nested attribute to a maximum of 65,535 bytes. The total action stream, however, was allowed to grow beyond this limit after a March 2025 change (commit `a1e64addf3ff`) removed a 32 KiB safety cap.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| ~2013 | Original vulnerable code path introduced in OVS kernel datapath |
| 2025-03 | Commit `a1e64addf3ff9257b45b78bc7d743781c3f41340` removes 32 KiB cap on generated action streams, exposing the wraparound bug |
| 2026-06-19 | Asim Manizada reports vulnerability to `security@kernel.org` and OVS maintainers |
| 2026-07-24 | Patch (commit `3f1f75536668`) merged into stable kernel trees |
| 2026-07-28 06:00 | Public disclosure: writeup and PoC released after coordinated embargo |
| 2026-08-01+ | Security advisories published by major distributions |

## Root Cause: Integer Wraparound in OVS Netlink Action Length

The vulnerability exists in the `add_nested_action_end()` function within the kernel's OVS implementation. When finalizing a nested action group, it calculates the length as:

```c
a->nla_len = sfa->actions_len - st_offset;
```

This assignment performs no bounds check. The `nla_len` field is 16 bits wide (`u16`), so when the generated action stream exceeds 65,535 bytes, the subtraction wraps to a small value. Subsequent parsing code trusts this wrapped length and resumes reading at an incorrect offset -- landing inside attacker-controlled data within the same contiguous buffer.

## Technical Analysis of the Exploitation Chain

### 1. Triggering the Wraparound (Namespace + CLONE/CT Packing)

The exploit begins by creating an isolated user and network namespace:

```bash
unshare -Urn
```

This gives the attacker `CAP_NET_ADMIN` within the new namespace without requiring any host-level privileges. From inside this namespace, the exploit resolves the OVS Generic Netlink family name, which auto-loads `openvswitch.ko` if not already present.

The attacker then submits a `CLONE` action containing approximately 400 conntrack (`CT`) sub-actions. Each CT action expands to ~164 bytes during kernel processing:

- Total generated size: `4 + 8 + 400 * 164 = 65,612 bytes`
- Stored `nla_len = 65,612 mod 65,536 = 76` (0x004c)

The parser trusts the wrapped length (76 bytes) and resumes parsing at offset 0x004c -- which falls inside the first CT action's labels/timeout fields, an area the attacker controls via CT label values embedded in the original flow.

### 2. Primitive 1: Kernel Pointer Leak via Fake OUTPUT Action

The attacker places a fake `OUTPUT` action with `nla_len=512` at the wraparound landing point (offset 0x004c within CT labels). The oversized length causes the action's "payload" to span into adjacent generated CT actions containing real function pointers -- specifically, pointers to the FTP conntrack helper (`nf_conntrack_ftp.ko`).

When OVS dumps the flow back to userspace, it serializes this memory region, leaking kernel addresses that allow the attacker to derive the kernel base address (defeating KASLR).

### 3. Primitive 2: Arbitrary Kernel Read via Fake Tunnel SET Action

A fake tunnel `SET` action with an attacker-controlled `tun_dst` pointer forces OVS to read tunnel metadata fields from arbitrary kernel memory:

```c
tun_dst = target_address - field_offset
```

Different tunnel fields (TOS, TTL, port, IPv4 address) allow reading individual bytes at varying offsets from the target address. When OVS serializes tunnel attributes back to userspace, the attacker receives the contents of arbitrary kernel memory.

### 4. Primitive 3: Targeted 32-bit Decrement via Teardown

The same fake tunnel `SET` action triggers reference-count manipulation during flow cleanup:

```c
dst_release((struct dst_entry *)ovs_tun->tun_dst);
```

By setting `tun_dst = target_address - dst_refcount_offset`, each flow deletion performs a single decrement at the target address. The attacker chains multiple flow deletions to precisely decrement specific fields.

### 5. Privilege Escalation: Credential Corruption

The complete exploitation chain:

1. **Leak kernel base** via FTP helper pointer chain traversal (Primitive 1)
2. **Locate `init_pid_ns`** using kernel symbol offsets derived from the ~800 pre-built kernel records (or dynamically via `/proc/kallsyms`, `System.map`, or BTF data)
3. **Find attacker's `task_struct`** in the host PID namespace IDR
4. **Read credential pointer** from the task structure (Primitive 2)
5. **Decrement `fsuid`/`fsgid`** fields to zero on modern kernels, OR decrement `__capability` words to wrap to `0xffffffff` on older kernels (Primitive 3)
6. **Write `/etc/sudoers.d/` or `/etc/sudoers`** with elevated privileges (passwordless sudo rule injection)
7. **Spawn root shell**

### 6. Anti-Forensics / Evasion Techniques

The exploit is explicitly destructive by design:
- Forks a host-side writer process that persists after exploit completion
- Leaves detached processes and corrupted OVS state to prevent safe teardown
- Corrupts live kernel credentials persistently (requires reboot for full cleanup)
- AppArmor bypass variant uses `aa-exec -p trinity -- unshare -Urn`

### 7. Platform-Specific Behavior

#### Linux (x86-64 Only)

- **Architecture:** x86-64 only (struct layout and expansion ratios are architecture-specific)
- **Delivery:** Python 3.7+ script (`ovswrap-poc.py`)
- **Prerequisites:** OVS kernel module available (built-in or loadable), unprivileged user namespaces enabled (default on most distros), conntrack with labels, FTP conntrack helper, `sudo` installed
- **No prerequisites needed:** No existing OVS bridge, no running `ovs-vswitchd`, no host-level `CAP_NET_ADMIN`
- **Dynamic fallback:** When pre-built records don't match the running kernel, the PoC attempts dynamic derivation using `pahole`, `/proc/kallsyms`, `System.map`, or kernel BTF data

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `openvswitch.ko` | Kernels 5.15.180-211, 6.1.132-177, 6.6.84-144, 6.12.20-96, 6.18.0-39, 7.1.0-4 | Vulnerable kernel module with missing `nla_len` bounds check |
| `ovswrap-poc.py` | N/A (PoC) | Public exploit script with ~800 pre-built kernel records |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `/etc/sudoers.d/*` | N/A (modified) | Passwordless sudo rule injected by exploit post-exploitation |
| Linux | `/etc/sudoers` | N/A (modified) | Alternative target for sudo rule injection |
| Linux | `/etc/modprobe.d/ovswrap.conf` | N/A | Mitigation file blocking OVS module load |

### Network

No network IOCs -- this is a local-only privilege escalation vulnerability with no remote attack vector.

### Behavioral

- **Namespace creation:** Unprivileged `unshare -Urn` invocation creating user + network namespace
- **AppArmor bypass:** `aa-exec -p trinity -- unshare -Urn` variant
- **Module auto-load:** Generic Netlink family resolution triggering `openvswitch.ko` and `nf_conntrack_ftp.ko` load from user namespace
- **Credential corruption:** Modification of kernel `cred` structure fields (`fsuid`, `fsgid`, or capability words) via targeted memory decrement
- **Sudoers injection:** Unauthorized writes to `/etc/sudoers` or `/etc/sudoers.d/` following credential corruption
- **Persistent kernel corruption:** Detached processes and corrupted OVS state remaining after exploitation

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | Kernel memory corruption via OVS `nla_len` wraparound to escalate from unprivileged user to root |
| T1611 | Escape to Host | Use of `unshare -Urn` to create user/network namespace, then exploiting kernel module to affect host credentials |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Post-exploitation injection of passwordless sudo rules into `/etc/sudoers.d/` |
| T1014 | Rootkit (Kernel Credential Manipulation) | Direct manipulation of kernel `cred` structure to zero out `fsuid`/`fsgid` or wrap capability fields |
| T1547.006 | Boot or Logon Autostart Execution: Kernel Modules and Extensions | Auto-loading `openvswitch.ko` via Generic Netlink family resolution from unprivileged context |

## Impact Assessment

**Breadth:** Virtually all major Linux distributions shipping kernels in the affected version ranges are vulnerable in default configuration. The broad availability of pre-built kernel records (~800 builds) and dynamic derivation fallback means the exploit is viable across a very large installed base.

**Depth:** Complete system compromise -- the attacker gains persistent root access via sudoers modification and direct kernel credential corruption. The exploit is deterministic (no race conditions, no heap grooming), achieving "logic-bug-grade reliability."

**Stealth:** Moderate -- the exploit creates observable artifacts (namespace creation, module loads, sudoers modification) but operates entirely locally with no network indicators. Kernel credential corruption may not trigger traditional file-integrity monitoring unless sudoers files are specifically watched.

**Exposure window:** The underlying bug existed for approximately 13 years; the exploitable configuration (without the 32 KiB cap) has existed since March 2025. Public PoC availability since July 28, 2026 means active exploitation is likely.

## Detection & Remediation

### Immediate Detection

Check if the vulnerable module is loaded:
```bash
lsmod | grep openvswitch
```

Check for unauthorized sudoers modifications:
```bash
find /etc/sudoers.d/ -newer /etc/sudoers -type f -ls
stat /etc/sudoers
```

Check for suspicious namespace creation:
```bash
# Check audit logs for unshare syscalls
ausearch -sc unshare --start today
```

Check kernel version against fixed releases:
```bash
uname -r
# Compare against first-fixed: 5.15.212, 6.1.178, 6.6.145, 6.12.97, 6.18.40, 7.1.5
```

### Remediation

1. **Immediate mitigation -- block OVS module load:**
   ```bash
   echo 'install openvswitch /bin/false' > /etc/modprobe.d/ovswrap.conf
   ```
   If the module is already loaded, remove it (only if not actively used):
   ```bash
   modprobe -r openvswitch
   ```

2. **Disable unprivileged user namespaces** (if not needed by containers/Flatpak):
   ```bash
   sysctl -w kernel.unprivileged_userns_clone=0
   echo 'kernel.unprivileged_userns_clone=0' >> /etc/sysctl.d/99-ovswrap.conf
   ```

3. **Deploy BPF guard** (available in the PoC repository's `bpf-mitigation/` directory) as an emergency measure.

4. **Patch the kernel** to fixed versions: 5.15.212, 6.1.178, 6.6.145, 6.12.97, 6.18.40, or 7.1.5+.

5. **Audit for compromise:** Check `/etc/sudoers` and `/etc/sudoers.d/` for unauthorized entries; review `auth.log`/`secure` for unexpected sudo usage; check for orphaned processes with corrupted credentials.

6. **Reboot** after patching to fully clear corrupted kernel state and detached exploit processes.

### Long-Term Hardening

- Restrict unprivileged user namespace creation to only applications that require it (e.g., container runtimes)
- Implement file integrity monitoring on `/etc/sudoers` and `/etc/sudoers.d/`
- Deploy auditd rules monitoring `unshare` syscall usage and kernel module loads
- Maintain kernel patching SLAs -- this class of vulnerability (kernel memory corruption exposed by configuration change) can emerge at any time in long-standing code

## Detection Rules

These detections target the OVSwrap (CVE-2026-64531) exploitation chain at multiple stages: PoC execution, namespace creation, module loading, and post-exploitation sudoers modification. All Sigma rules convert to Splunk and CrowdStrike LogScale; `sigma check` was unable to validate ATT&CK tags due to a network-blocked MITRE data endpoint, but all other validators passed with 0 errors. Compiles does not equal fires -- verify in your pipeline with representative telemetry.

### Sigma: OVSwrap Exploit Script Execution

Detects execution of the OVSwrap PoC exploit script by matching on the distinctive `ovswrap` string in process creation events.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (excl. attacktag, network-blocked MITRE endpoint); splunk 0; log_scale 0. Keys on distinctive "ovswrap" string from published PoC name. Low FP risk -- string is unique to this exploit. Evasion: trivial rename defeats this; pair with behavioral rules below. -->
```yaml
title: OVSwrap Exploit Script Execution - CVE-2026-64531
id: 8d3f1a2e-7b4c-4e5d-9f6a-2c1b0d8e7f3a
status: experimental
description: >
    Detects execution of the OVSwrap (CVE-2026-64531) proof-of-concept exploit
    script targeting Linux kernel Open vSwitch local privilege escalation.
    The PoC is a Python script named ovswrap-poc.py that chains namespace
    creation with OVS Generic Netlink manipulation for credential corruption.
references:
    - https://heyitsas.im/posts/ovswrap/
    - https://github.com/manizada/OVSwrap
    - https://www.openwall.com/lists/oss-security/2026/07/28/8
author: Actioner
date: 2026/08/06
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: linux
detection:
    selection_script:
        CommandLine|contains: 'ovswrap'
    selection_poc_name:
        Image|endswith:
            - '/ovswrap-poc.py'
            - '/ovswrap'
    selection_cmdline_pattern:
        CommandLine|contains|all:
            - 'python'
            - 'ovswrap'
    condition: selection_script or selection_poc_name or selection_cmdline_pattern
falsepositives:
    - Legitimate security testing with documented change management
level: high
```

### Sigma: Suspicious Unshare Namespace Creation for OVS Exploitation

Detects `unshare -Urn` (user+network namespace) invocation and the AppArmor bypass variant (`aa-exec -p trinity`), both prerequisite commands for OVSwrap exploitation. Scope to non-container hosts to reduce noise.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (excl. attacktag); splunk 0; log_scale 0. unshare -Urn is legitimate in container/Flatpak contexts, hence medium confidence. The aa-exec trinity variant is more specific. FP: container runtimes, Flatpak, snap. -->
```yaml
title: Suspicious Unshare Namespace Creation for OVS Exploitation
id: 4a7e2f9b-1c3d-4856-ae90-5b8d6c7f1e2a
status: experimental
description: >
    Detects suspicious use of unshare with user and network namespace flags
    (-Urn) which is the prerequisite for the OVSwrap (CVE-2026-64531) exploit
    to obtain CAP_NET_ADMIN without host privileges. Also detects the
    AppArmor bypass variant using aa-exec.
references:
    - https://heyitsas.im/posts/ovswrap/
    - https://github.com/manizada/OVSwrap
author: Actioner
date: 2026/08/06
tags:
    - attack.t1068
    - attack.t1611
logsource:
    category: process_creation
    product: linux
detection:
    selection_unshare:
        Image|endswith: '/unshare'
        CommandLine|contains|all:
            - '-U'
            - '-r'
            - '-n'
    selection_aa_exec_bypass:
        CommandLine|contains|all:
            - 'aa-exec'
            - 'trinity'
            - 'unshare'
    condition: selection_unshare or selection_aa_exec_bypass
falsepositives:
    - Container runtimes creating user namespaces
    - Development environments using namespace isolation
    - Flatpak or snap sandbox creation
level: medium
```

### Sigma: Unauthorized Sudoers Modification (OVSwrap Post-Exploitation)

Detects writes to `/etc/sudoers` or `/etc/sudoers.d/` by processes other than package managers or `visudo`, which is the post-exploitation payload of OVSwrap.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (excl. attacktag); splunk 0; log_scale 0. Sudoers modification outside package management is a strong signal. Filter excludes dpkg/rpm/yum/dnf/apt/visudo. FP: Ansible/Puppet/Chef config management -- add filters for your environment. -->
```yaml
title: Unauthorized Sudoers Modification After OVS Exploitation
id: 6c9d3e1f-5a2b-4c7d-8e4f-3b6a0d9e8f1c
status: experimental
description: >
    Detects modification of /etc/sudoers or files in /etc/sudoers.d/ which
    is the post-exploitation payload of the OVSwrap (CVE-2026-64531) exploit.
    The exploit corrupts kernel credentials then injects passwordless sudo
    rules to persist root access.
references:
    - https://heyitsas.im/posts/ovswrap/
    - https://github.com/manizada/OVSwrap
author: Actioner
date: 2026/08/06
tags:
    - attack.t1548.003
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|startswith:
            - '/etc/sudoers'
            - '/etc/sudoers.d/'
    filter_package_manager:
        Image|endswith:
            - '/dpkg'
            - '/rpm'
            - '/yum'
            - '/dnf'
            - '/apt'
            - '/apt-get'
            - '/visudo'
    condition: selection and not filter_package_manager
falsepositives:
    - Legitimate system administration via configuration management tools
    - Ansible, Puppet, Chef automated sudoers management
level: high
```

### Sigma: Suspicious OpenVSwitch Kernel Module Load

Detects `modprobe` or `insmod` loading `openvswitch` or `nf_conntrack_ftp` modules, which is the first step in OVSwrap exploitation (auto-triggered by Generic Netlink family resolution from a user namespace).
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (excl. attacktag); splunk 0; log_scale 0. Module loading is normal in OVS/SDN environments, hence medium confidence. Best used as a correlating signal alongside the namespace creation rule. FP: legitimate OVS deployments, container networking. -->
```yaml
title: Suspicious OpenVSwitch Kernel Module Load
id: 2e8b5d4c-9a1f-4367-bf2e-7c6d0a3e5f9b
status: experimental
description: >
    Detects loading of the openvswitch or nf_conntrack_ftp kernel modules
    which may indicate preparation for CVE-2026-64531 (OVSwrap) exploitation.
    The exploit triggers auto-loading of openvswitch.ko by resolving the OVS
    Generic Netlink family from within a user namespace.
references:
    - https://heyitsas.im/posts/ovswrap/
    - https://github.com/manizada/OVSwrap
author: Actioner
date: 2026/08/06
tags:
    - attack.t1068
logsource:
    category: process_creation
    product: linux
detection:
    selection_modprobe:
        Image|endswith: '/modprobe'
        CommandLine|contains:
            - 'openvswitch'
            - 'nf_conntrack_ftp'
    selection_insmod:
        Image|endswith: '/insmod'
        CommandLine|contains:
            - 'openvswitch'
            - 'nf_conntrack_ftp'
    condition: selection_modprobe or selection_insmod
falsepositives:
    - Legitimate OVS deployment in virtualization or SDN environments
    - Container orchestration platforms loading OVS for networking
level: medium
```

### YARA: OVSwrap Exploit PoC Detection

Detects the OVSwrap exploit script/binary by matching on distinctive strings from the published PoC (CVE ID, exploit name, kernel function targets, and operational commands).
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac 0. Positive sample (constructed from published PoC header strings) matched; negative sample (benign network script) silent. Keys on "ovswrap" + "CVE-2026-64531" combo and fallback on 3+ kernel function names + 2+ operational commands. FP: security research tools discussing CVE-2026-64531 in depth could match -- acceptable for a file-scan rule. -->
```yara
rule Exploit_CVE_2026_64531_OVSwrap_PoC
{
    meta:
        description = "Detects the OVSwrap (CVE-2026-64531) proof-of-concept exploit script targeting Linux kernel Open vSwitch local privilege escalation"
        author = "Actioner"
        date = "2026-08-06"
        reference = "https://github.com/manizada/OVSwrap"
        severity = "critical"

    strings:
        $s1 = "ovswrap" ascii nocase
        $s2 = "CVE-2026-64531" ascii
        $s3 = "add_nested_action_end" ascii
        $s4 = "nla_len" ascii
        $s5 = "sw_flow_actions" ascii
        $s6 = "dst_release" ascii
        $s7 = "init_pid_ns" ascii
        $s8 = "tun_dst" ascii

        $cmd1 = "unshare -Urn" ascii
        $cmd2 = "/etc/sudoers" ascii
        $cmd3 = "aa-exec" ascii
        $cmd4 = "openvswitch" ascii
        $cmd5 = "nf_conntrack_ftp" ascii
        $cmd6 = "CAP_NET_ADMIN" ascii

        $poc1 = "ovswrap-poc" ascii
        $poc2 = "manizada" ascii
        $poc3 = "kernel_pointer_leak" ascii nocase
        $poc4 = "arbitrary_kernel_read" ascii nocase
        $poc5 = "targeted_decrement" ascii nocase
        $poc6 = "credential_corruption" ascii nocase

    condition:
        filesize < 5MB and
        (
            ($s1 and $s2) or
            ($poc1 and 2 of ($cmd*)) or
            (3 of ($s*) and 2 of ($cmd*)) or
            (3 of ($poc*))
        )
}
```

### Snort: N/A

No network indicators -- OVSwrap is a local-only kernel privilege escalation with no remote attack vector, C2 communication, or network-based exploitation path.

### Suricata: N/A

No network indicators -- same rationale as Snort above.

## Lessons Learned

1. **Legacy code + configuration changes = new attack surface.** The vulnerable code existed for 13 years but was unexploitable due to a 32 KiB cap on action streams. A seemingly innocuous configuration change in March 2025 exposed it. Kernel changes that relax limits or remove bounds checks on existing code paths deserve heightened review.

2. **Auto-loadable kernel modules are a persistent risk.** The OVS module's ability to be auto-loaded via Generic Netlink resolution from unprivileged user namespaces meant that systems not actively using OVS were still vulnerable. Organizations should audit which kernel modules are auto-loadable and restrict module loading where possible.

3. **Unprivileged user namespaces continue to expand attack surface.** This is the latest in a series of kernel privilege escalation vulnerabilities reachable through unprivileged user namespaces. Organizations not requiring them for container workloads should disable them as a defense-in-depth measure.

4. **Deterministic exploits demand rapid patching.** Unlike traditional heap corruption vulnerabilities that require probabilistic grooming, OVSwrap's deterministic wraparound means the PoC achieves near-100% reliability. Pre-built records for ~800 kernel builds lower the bar further. Patching timelines should reflect this reliability.

## Sources

- [Asim Manizada - OVSwrap Technical Writeup](https://heyitsas.im/posts/ovswrap/) -- primary researcher disclosure with full technical details of the vulnerability mechanism and exploitation chain
- [OVSwrap PoC Repository](https://github.com/manizada/OVSwrap) -- public proof-of-concept code, pre-built kernel records, and BPF mitigation
- [oss-security Mailing List Disclosure](https://www.openwall.com/lists/oss-security/2026/07/28/8) -- coordinated disclosure post to oss-security
- [The Hacker News - New OVSwrap Linux Kernel Flaw](https://thehackernews.com/2026/08/new-ovswrap-linux-kernel-flaw-lets.html) -- news coverage with distribution impact analysis
- [Security Affairs - OVSwrap 13-Year-Old Linux Kernel Flaw](https://securityaffairs.com/196657/hacking/ovswrap-13-year-old-linux-kernel-flaw-lets-local-users-become-root.html) -- news coverage with affected distribution matrix
- [CloudLinux Advisory](https://cloudlinux.zendesk.com/hc/en-us/articles/29223197225116-Kernel-Local-Privilege-Escalation-CVE-2026-64531-OVSwrap-Open-vSwitch-Affected-Status-and-Fix) -- vendor-specific mitigation and fix status

---
*Report generated by Actioner*
