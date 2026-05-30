# Technical Analysis Report: CIFSwitch — Linux CIFS/keyring Local Privilege Escalation (2026-05-30)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-05-30
Version: 1 (DRAFT)

## Executive Summary

CIFSwitch is a local privilege escalation (LPE) affecting the Linux kernel CIFS client in combination with the userspace `cifs-utils` upcall helper (`cifs.upcall`). The kernel's `cifs.spnego` key type did not verify that key requests originate from the kernel CIFS client, so any unprivileged user could call `request_key("cifs.spnego", <forged description>, ...)` (or `add_key`) and inject authority-bearing fields (`pid`, `uid`, `creduid`, `upcall_target`) that `cifs.upcall` trusts as kernel-supplied. With `upcall_target=app`, the root-running `cifs.upcall` switches into the attacker's user/mount namespace and performs an NSS lookup (`getpwuid`) **before** dropping privileges, loading an attacker-supplied `libnss_*.so.2` from that namespace as root — yielding code execution as root (the public PoC drops a `sudoers.d` entry).

The flaw was disclosed 2026-05-27 by researcher Asim Manizada with a full writeup and a public PoC. The underlying logic traces to 2007. It affects multiple distributions in stock configuration (Linux Mint, Kali, Rocky/Alma/CentOS Stream 9, SLES 15 SP7) wherever a compatible `cifs-utils` (6.14+ or backported) is present and unprivileged user-namespace creation is enabled. A CVE was pending at publication. **Distinct from** the separately tracked CVE-2026-1015 LPE in `summaries/2026-05-30-linux-kernel-cve-2026-1015-lpe.md`.

## Background: Linux CIFS client + cifs-utils upcall

When the kernel CIFS client needs SPNEGO/Kerberos credentials for a mount, it creates a `cifs.spnego` request key. The kernel's `request-key` mechanism resolves it via `/etc/request-key.d/cifs.spnego.conf` (`create cifs.spnego * * /usr/sbin/cifs.upcall %k`), launching `/usr/sbin/cifs.upcall` as **root**. `cifs.upcall` reads the key *description* to learn which user/host/credentials to act for. The design assumed only the kernel could create that key type — CIFSwitch breaks that assumption.

## Root Cause: missing origin check on cifs.spnego key creation

The kernel exposed `cifs.spnego` as a normal keyring key type, so userspace could create it directly via `request_key(2)`/`add_key(2)`. Because the description's `pid`/`uid`/`creduid`/`upcall_target` fields are attacker-controlled, an unprivileged user steers the root-running `cifs.upcall` helper: `upcall_target=app` makes the helper call `switch_to_process_ns(arg->pid)` into the attacker's namespace, then `getpwuid()` loads a malicious NSS module as root before `setuid()`.

The upstream fix (commit `3da1fdf4efbc490041eb4f836bf596201203f8f2`, "smb: client: reject userspace cifs.spnego descriptions", `fs/smb/client/cifs_spnego.c`) adds `cifs_spnego_key_vet_description()`, which returns `-EPERM` unless the requesting credential matches the kernel's private `spnego_cred` — blocking userspace-created `cifs.spnego` keys.

## Technical Analysis of the Exploit Chain

### 1. Namespace setup
The PoC runs under `unshare -Ur -m` (new user namespace with root mapping, new mount namespace), establishing an environment whose NSS modules the attacker controls.

### 2. Forged key request
From userspace:
- `syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, "cifs-upcall-sudoers-poc", 0, 0, 0)`
- `syscall(__NR_request_key, "cifs.spnego", desc, "", KEY_SPEC_SESSION_KEYRING)`

with the forged description:
`ver=0x2;host=example.com;ip4=127.0.0.1;sec=krb5;uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root`

(Compare the legitimate kernel-emitted form: `ver=0x2;host=fs.acme.com;ip4=192.168.1.10;sec=krb5;uid=0x3e8;creduid=0x3e8;user=test@ACME.COM;pid=0x4f2a;upcall_target=app`.)

### 3. Root NSS load
The kernel upcall launches `/usr/sbin/cifs.upcall` as root; `upcall_target=app` makes it enter the PoC's namespace, then `getpwuid()` loads the attacker's fake NSS module `libnss_pwn.so.2`, executing attacker code as root.

### 4. Persistence / proof
The fake NSS module writes a sudoers drop: `/etc/sudoers.d/cifs-upcall-poc-<token>` containing `<user> ALL=(ALL:ALL) NOPASSWD: ALL`.

## Indicators of Compromise (IOCs)

> Defanging convention applies to network IOCs only; the values below are local file/exploit artifacts (not defanged — they are the real detection strings).

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Linux | `libnss_pwn.so.2` (in common x86_64 NSS dirs) | n/a (built at runtime by PoC) | Fake NSS module loaded as root by `cifs.upcall` |
| Linux | `/etc/sudoers.d/cifs-upcall-poc-<token>` | n/a | PoC sudoers drop granting NOPASSWD ALL |
| Linux | `/usr/sbin/cifs.upcall` | n/a | Legitimate root helper abused as the exploit's execution vector |

### Behavioral

- Unprivileged process issues `request_key`/`add_key` for key type `cifs.spnego` (kernel is the only legitimate creator).
- `cifs.upcall` runs as root with an ancestry involving `unshare`/user-namespace tooling rather than a kernel-driven CIFS mount.
- Forged key description containing `upcall_target=app` with attacker-chosen `pid`/`uid`.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1068 | Exploitation for Privilege Escalation | Forged `cifs.spnego` key drives root `cifs.upcall` to run attacker code |
| T1611 | Escape to Host | Root helper switches into attacker namespace, crossing the namespace boundary with root creds — applied here because the root-credentialed `cifs.upcall` crosses the user/mount-namespace boundary into the attacker's namespace (a root-credential namespace-boundary crossing), the same boundary-violation primitive T1611 captures, rather than the canonical container→host direction |
| T1574.006 | Hijack Execution Flow: Dynamic Linker / Shared Object | Malicious `libnss_pwn.so.2` loaded as root before privilege drop |

## Impact Assessment

Any local unprivileged user on an affected, default-configured distribution with `cifs-utils` installed and unprivileged user namespaces enabled can obtain root, typically in seconds. Broad distro exposure; no remote vector (purely local). Stealth is moderate — the chain leaves distinctive process and file artifacts (below).

## Detection & Remediation

### Immediate Detection
- Check for the PoC sudoers artifact: look for files matching `/etc/sudoers.d/cifs-upcall-poc-*`.
- Hunt for `libnss_pwn.so.2` anywhere on disk.
- Audit `cifs.upcall` executions whose parent is not the kernel `request-key` flow.

### Remediation
1. Apply the kernel patch (commit `3da1fdf4efbc490041eb4f836bf596201203f8f2`) once your distro ships it; track the eventual CVE.
2. Until patched, evaluate the interim mitigations below — efficacy is configuration-dependent (see caveats).

### Long-Term Hardening (advisory — config-dependent, NOT guaranteed fixes)
- **Disable unprivileged user namespaces** (`sysctl kernel.unprivileged_userns_clone=0` / `user.max_user_namespaces=0`): removes the namespace primitive the PoC relies on — but breaks legitimate sandboxing and may not cover every exploit variant.
- **Override the request-key rule** for `cifs.spnego` to a no-op/negate: blocks the upcall path but affects real CIFS/Kerberos mounts.
- **Blacklisting / unloading the `cifs` module is a NO-OP if CIFS is built-in (`CONFIG_CIFS=y`)** — on such kernels the module cannot be unloaded; treat module-blacklist advice as ineffective there and rely on the patch + namespace hardening instead.

## Detection Rules

These detections target CIFSwitch's host artifacts: the abused root `cifs.upcall` launched from an attacker namespace, the PoC's file drops (`libnss_pwn.so.2`, `/etc/sudoers.d/cifs-upcall-poc-*`), and unprivileged `cifs.spnego` key syscalls. All three Sigma rules compile and convert cleanly to Splunk and CrowdStrike (LogScale); no network rule applies (local LPE), and there is no malware sample for YARA. Note: compiles ≠ fires — validate field mappings against your Linux EDR/auditd pipeline before production.

### Sigma: CIFSwitch root cifs.upcall from attacker namespace
Detects `/usr/sbin/cifs.upcall` executions whose parent is `unshare` or the named PoC script, indicating the upcall was driven from an attacker-controlled namespace rather than a kernel CIFS mount.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0 (no issues); splunk 0; log_scale 0. The ParentImage|endswith '/cifswitch-poc.py' anchor is PoC-exact (high precision but trivially renamed); the '/unshare' anchor is the durable behavioral cue — legitimate cifs.upcall is parented by /sbin/request-key for a live mount, never by unshare. T1611 (namespace escape) + T1068. Tune: in environments that legitimately wrap cifs.upcall in namespaces this could FP; add an allowlist of known callers. -->
```yaml
title: CIFSwitch - cifs.upcall Spawned From Userspace Key Request (LPE)
id: 7c1e2a3b-4d5f-4a6b-8c9d-0e1f2a3b4c5d
status: experimental
description: >
    Detects the CIFSwitch local privilege escalation pattern where an unprivileged
    user forges a cifs.spnego key request, causing the request-key upcall helper to
    launch /usr/sbin/cifs.upcall as root. Legitimately, cifs.upcall is invoked by the
    kernel's request-key mechanism (parent /sbin/request-key) for an active CIFS mount;
    here it is reachable from an attacker-controlled namespace setup. Flags cifs.upcall
    executions whose ancestry includes unshare/namespace tooling.
references:
    - https://heyitsas.im/posts/cifswitch/
    - https://github.com/manizada/CIFSwitch
    - https://www.bleepingcomputer.com/news/security/new-cifswitch-linux-flaw-gives-root-on-multiple-distributions/
author: Actioner
date: 2026-05-30
tags:
    - attack.t1068
    - attack.t1611
logsource:
    category: process_creation
    product: linux
detection:
    selection_upcall:
        Image|endswith: '/cifs.upcall'
    selection_ns_ancestry:
        ParentImage|endswith:
            - '/unshare'
            - '/cifswitch-poc.py'
    condition: selection_upcall and selection_ns_ancestry
falsepositives:
    - Administrators manually testing cifs.upcall within a namespace
level: high
```

### Sigma: CIFSwitch malicious NSS module / sudoers drop
Detects the PoC's payload artifacts on disk: the fake NSS module `libnss_pwn.so.2` and the `/etc/sudoers.d/cifs-upcall-poc-*` privilege grant.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Both names are PoC-literal (from cifswitch-poc.py): high precision, near-zero benign overlap, but a real attacker would rename them — pair with the process and syscall rules for the durable chain. T1574.006 (shared object hijack) + T1068. file_event/product:linux maps to Sysmon-for-Linux EID 11 / auditd PATH (TargetFilename); confirm your pipeline field naming. -->
```yaml
title: CIFSwitch - Malicious NSS Module or sudoers.d Drop (LPE Payload)
id: 9a8b7c6d-5e4f-4a3b-2c1d-0f9e8d7c6b5a
status: experimental
description: >
    Detects the file-drop artifacts of the CIFSwitch (cifs.upcall) local privilege
    escalation PoC: a fake NSS module named libnss_pwn.so.2 loaded by the root
    cifs.upcall helper after a namespace switch, and/or a sudoers drop matching
    /etc/sudoers.d/cifs-upcall-poc-*. These names come directly from the public PoC.
references:
    - https://github.com/manizada/CIFSwitch
    - https://heyitsas.im/posts/cifswitch/
author: Actioner
date: 2026-05-30
tags:
    - attack.t1068
    - attack.t1574.006
logsource:
    category: file_event
    product: linux
detection:
    selection_nss:
        TargetFilename|endswith: '/libnss_pwn.so.2'
    selection_sudoers:
        TargetFilename|startswith: '/etc/sudoers.d/cifs-upcall-poc-'
    condition: selection_nss or selection_sudoers
falsepositives:
    - None expected; both names are exploit-specific PoC artifacts
level: high
```

### Sigma: CIFSwitch unprivileged cifs.spnego key syscall (auditd)
Hunt-only: flags non-root `request_key`/`add_key` syscalls — the syscall family used to forge the `cifs.spnego` key; pair with the process/file rules to confirm CIFSwitch (keyring syscalls alone are common).
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check 0 (uid:0 -> unquoted int to clear NumberAsStringIssue); splunk 0; log_scale 0. Encoding note: auditd SYSCALL records the syscall by NAME when interpreted (auditd -i / ausearch -i): x86_64 add_key=248, request_key=249, keyctl=250 (decimal syscall numbers) — this rule keys on the interpreted NAME field, not a numeric arg. The cifs.spnego key-TYPE string is passed via a pointer arg, so it is NOT present in raw a0..a3 (hex) and cannot be matched from the SYSCALL record alone; hence we anchor on syscall name + non-root uid and rely on the process/file rules for specificity. Broad by design (keyring use is legitimate for krb5/gnome-keyring) -> medium confidence, hunt-only; tune with exe allowlists. -->
```yaml
title: CIFSwitch - Userspace request_key/add_key for cifs.spnego Key Type
id: 1f2e3d4c-5b6a-4978-8a6b-7c8d9e0f1a2b
status: experimental
description: >
    Detects userspace invocation of the request_key/add_key/keyctl syscalls associated
    with forging a cifs.spnego key (CIFSwitch LPE). The kernel CIFS client is the only
    legitimate creator of cifs.spnego keys; an unprivileged process issuing these key
    syscalls is anomalous and precedes the cifs.upcall root helper launch. On x86_64
    auditd records the syscall by name when interpreted (add_key=248, request_key=249,
    keyctl=250); this rule matches the interpreted syscall names.
references:
    - https://heyitsas.im/posts/cifswitch/
    - https://github.com/torvalds/linux/commit/3da1fdf4efbc490041eb4f836bf596201203f8f2
author: Actioner
date: 2026-05-30
tags:
    - attack.t1068
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'SYSCALL'
        syscall:
            - 'request_key'
            - 'add_key'
    filter_root:
        uid: 0
    condition: selection and not filter_root
falsepositives:
    - Legitimate keyring-using software run as non-root (e.g. krb5/gnome-keyring) - tune by adding exe filters
level: medium
```

### Snort: N/A
Local privilege escalation with no network vector — no Snort rule applies.

### Suricata: N/A
Local privilege escalation with no network vector — no Suricata rule applies.

### YARA: N/A
No malware sample; the PoC builds helpers at runtime. The `libnss_pwn.so.2` / `sudoers.d` artifacts are covered more reliably by the file_event Sigma rule than by a YARA string signature.

## Lessons Learned

Trust boundaries on kernel keyring key types must be explicit: a key type meant to be kernel-created should reject userspace `request_key`/`add_key`, as the fix now does. Root helpers that enter caller-controlled namespaces before dropping privileges are dangerous — NSS/dynamic-linker lookups must happen after `setuid()`, not before. Long-lived logic bugs (here, since 2007) can remain latent until a new primitive (unprivileged user namespaces) makes them exploitable.

## Sources

- [BleepingComputer — New CIFSwitch Linux flaw gives root on multiple distributions](https://www.bleepingcomputer.com/news/security/new-cifswitch-linux-flaw-gives-root-on-multiple-distributions/) — disclosure news, affected distros, mitigations
- [Asim Manizada — CIFSwitch technical writeup](https://heyitsas.im/posts/cifswitch/) — primary researcher analysis: mechanism, key description format, namespace/NSS chain
- [GitHub — manizada/CIFSwitch (PoC)](https://github.com/manizada/CIFSwitch) — public proof-of-concept; exact syscalls, forged description, libnss_pwn.so.2 / sudoers.d artifacts
- [Linux kernel commit 3da1fdf4efbc — smb: client: reject userspace cifs.spnego descriptions](https://github.com/torvalds/linux/commit/3da1fdf4efbc490041eb4f836bf596201203f8f2) — upstream fix and root-cause description
- [securityonline.info — CIFSwitch Local Root Exploit: PoC Disclosed](https://securityonline.info/cifswitch-local-root-exploit-poc/) — corroborating technical summary
- [Linuxiac — CIFSwitch Vulnerability Exposes Some Linux Distros to Local Root Access](https://linuxiac.com/cifswitch-vulnerability-exposes-some-linux-distros-to-local-root-access/) — corroborating coverage of affected distros and conditions

---
*Report generated by Actioner*
