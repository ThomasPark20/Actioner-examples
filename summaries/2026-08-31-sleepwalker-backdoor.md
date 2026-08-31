# SLEEPWALKER Backdoor -- DRAFT Technical Analysis

<!-- revision: 2026-08-31 -- Registry rule: removed standalone NullSessionPipes selection (too broad), condition now selection_anon only, level high->medium, confidence LOW. ATT&CK fixes: T1562.001->T1562, T1059->T1620, T1071 narrowed to SMB only, T1055 removed (replaced by T1620), T1027->T1573. YARA hash confidence CRITICAL->HIGH. Sources: folded Reichel into THN citation. IOC defanging: removed from file indicators (no network IOCs exist). -->

> **Status:** DRAFT -- File indicators are not defanged; no network IOCs exist to defang. Detection rules are PoC-grade and require validation in target environments before production deployment.
>
> **Date:** 2026-08-31
>
> **Classification:** TLP:CLEAR

---

## Executive Summary

SLEEPWALKER is a novel Windows backdoor discovered on August 26, 2026, that achieves stealth by remaining completely dormant until activated by a specially crafted network packet. The malware is an unsigned 64-bit DLL (59,904 bytes) that masquerades as `dpapi.dll` and is loaded via DLL search-order hijacking through ESET's `ERAAgent.exe` management agent. Once activated, a custom 23-instruction bytecode interpreter executes attacker-supplied commands entirely in memory. The backdoor contains no hardcoded C2 infrastructure -- no domains, IPs, or URLs -- making traditional network-based detection ineffective. Its multi-transport capability (TCP, UDP, ICMP, SMB named pipes, raw packet capture, and VMware VMCI) and use of AES-256-CCM encryption indicate a well-resourced, highly targeted operation.

---

## Background

The SLEEPWALKER backdoor was publicly documented by security researcher Reichel and reported by [The Hacker News](https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html) on August 26, 2026. The malware represents an evolution in passive backdoor design: rather than establishing outbound C2 channels that network monitoring can detect, it listens passively for inbound activation packets. This design philosophy mirrors earlier tools like passive implants used by advanced persistent threat groups, but adds a full bytecode interpreter for flexible post-activation capability.

The choice of ESET's management agent (`ERAAgent.exe`) as the host process is notable -- it runs with elevated privileges, is expected to generate network traffic, and its DLL loading behavior creates a reliable side-loading vector. The absence of registry run keys for persistence means the backdoor survives through the host service's own restart mechanism, reducing forensic artifacts.

---

## Technical Analysis

### DLL Side-Loading Mechanism

SLEEPWALKER exploits Windows DLL search-order behavior to load before the legitimate system `dpapi.dll`. The attack chain:

1. The attacker places a malicious `dpapi.dll` (or `dpapisvc.dll`) in the same directory as `ERAAgent.exe`.
2. When the ESET Management Agent service starts, Windows searches the application directory before `System32`, loading the attacker's DLL first.
3. The malicious DLL exports seven functions identical to the legitimate `dpapi.dll`, maintaining the appearance of a normal library.
4. No registry run keys or scheduled tasks are created -- persistence is inherited from the ESET service restart cycle.

**Detection indicator:** Any `dpapi.dll` or `dpapisvc.dll` file adjacent to `ERAAgent.exe` rather than in `C:\Windows\System32\` is anomalous.

### Custom Bytecode Interpreter

The backdoor implements a 23-instruction custom bytecode interpreter that:

- Executes attacker-supplied bytecode delivered via the activation packet
- Supports staged file delivery with SHA-256 integrity verification
- Enables in-memory code execution (fileless operation post-activation)
- Provides data movement and task scheduling capabilities

This design allows the attacker to evolve capabilities without replacing the implant, as new functionality is delivered as bytecode payloads.

### C2 Activation Model

Unlike conventional backdoors, SLEEPWALKER has **no built-in C2 infrastructure**:

- No domains, IP addresses, or URLs are embedded in the binary
- The backdoor makes no outbound connections on its own
- Activation requires a specifically crafted network packet containing valid bytecode
- All communications are encrypted with AES-256-CCM

**Network transports supported:**

| Transport | Use Case |
|-----------|----------|
| TCP | Standard remote activation |
| UDP | Lightweight, connectionless activation |
| ICMP | Covert channel (protocol commonly allowed through firewalls) |
| SMB Named Pipes | Lateral movement (includes credential support) |
| Raw Promiscuous Capture | Passive packet sniffing for activation triggers |
| VMware VMCI | Virtual machine-to-host or VM-to-VM communication |

The SMB named-pipe transport with embedded credentials suggests the operators plan for lateral movement within compromised environments. The VMware VMCI support indicates targeting of virtualized infrastructure.

### Evasion Techniques

- **No outbound network activity:** Passive activation defeats egress-based detection.
- **Legitimate host process:** Running inside ESET's management agent evades process-based allowlisting.
- **DLL masquerading:** Identical export table to the real `dpapi.dll` defeats static export analysis.
- **Unsigned binary:** The DLL is not code-signed, but this is obscured by loading within a trusted process context.
- **No registry persistence keys:** Avoids common persistence-detection heuristics.
- **AES-256-CCM encryption:** Prevents content inspection of activation packets and responses.
- **Fileless post-exploitation:** Bytecode execution occurs entirely in memory after activation.

### Registry Modifications

The backdoor modifies two registry areas to facilitate anonymous network access:

1. **`EveryoneIncludesAnonymous`** set to `1` -- allows anonymous users to be included in the "Everyone" group, weakening access controls.
2. **`NullSessionPipes`** -- unexpected pipe name entries are added, enabling unauthenticated access to specific named pipes used by the backdoor's SMB transport.

---

## Indicators of Compromise

> File indicators are presented as-is; no network IOCs exist for this threat.

### File Indicators

| Indicator | Value |
|-----------|-------|
| SHA-256 | `d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60` |
| MD5 | `2318327b29bb1c0e2d2b5f0211fc7fac` |
| File Type | Unsigned 64-bit Windows DLL |
| File Size | 59,904 bytes |
| Masquerade Name | dpapi.dll |
| Alternate Name | dpapisvc.dll |
| Host Process | ERAAgent.exe |
| Exported Functions | 7 (matching legitimate dpapi.dll) |

### Host Indicators

| Indicator | Detail |
|-----------|--------|
| Unexpected DLL | dpapi.dll or dpapisvc.dll adjacent to ERAAgent.exe |
| Registry Key | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous` = 1 |
| Registry Key | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes` (unexpected entries) |
| Encryption | AES-256-CCM static keys |

### Network Indicators

**None.** SLEEPWALKER contains no hardcoded network infrastructure (no domains, IPs, or URLs). Detection must rely on host-based indicators and behavioral analysis.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | SLEEPWALKER Usage |
|-------------|----------------|-------------------|
| [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | Hijack Execution Flow: DLL Search Order Hijacking | Malicious dpapi.dll placed alongside ERAAgent.exe |
| [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | Hijack Execution Flow: DLL Side-Loading | Unsigned DLL loaded by trusted ESET process |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Masquerading: Match Legitimate Name or Location | DLL named dpapi.dll with matching exports |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | EveryoneIncludesAnonymous and NullSessionPipes modifications |
| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Registry changes weaken OS access controls (EveryoneIncludesAnonymous) |
| [T1620](https://attack.mitre.org/techniques/T1620/) | Reflective Code Loading | Custom 23-instruction bytecode interpreter executes in-process |
| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | SMB named-pipe C2 transport |
| [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol | TCP, UDP, ICMP, raw packet capture, and VMCI activation |
| [T1570](https://attack.mitre.org/techniques/T1570/) | Lateral Tool Transfer | SMB named pipes with embedded credentials |
| [T1573](https://attack.mitre.org/techniques/T1573/) | Encrypted Channel | AES-256-CCM encrypted C2 communications |

---

## Impact Assessment

**Severity: HIGH**

- **Stealth:** The passive activation model and absence of network IOCs make detection significantly harder than conventional backdoors. Organizations relying solely on network-based detection (IDS/IPS, DNS monitoring, proxy logs) will not detect SLEEPWALKER.
- **Persistence:** Leveraging a legitimate security product's service restart cycle provides reliable, low-artifact persistence.
- **Flexibility:** The bytecode interpreter allows operators to deploy new capabilities without replacing the implant, reducing exposure.
- **Lateral Movement:** Built-in SMB named-pipe transport with credential support enables network propagation from a single foothold.
- **Virtualization Awareness:** VMCI support indicates the operators target environments with VMware infrastructure, potentially enabling hypervisor-level access.
- **Targeting:** The sophistication and resource investment (custom bytecode engine, multi-transport, targeted sideloading vector) suggest a state-sponsored or well-funded threat actor conducting targeted operations.

**Risk to ESET Customers:** Organizations running ESET Management Agent should prioritize scanning for unexpected DLLs in the ERAAgent installation directory. The sideloading vector does not exploit a vulnerability in ESET's software -- it exploits standard Windows DLL loading behavior.

---

## Detection and Remediation

### Detection Recommendations

1. **File System Monitoring:**
   - Alert on any `dpapi.dll` or `dpapisvc.dll` file creation outside of `C:\Windows\System32\` and `C:\Windows\SysWOW64\`.
   - Specifically monitor the ESET Management Agent installation directory for unexpected DLL files.

2. **Registry Monitoring:**
   - Alert on `EveryoneIncludesAnonymous` being set to `1` under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\`.
   - Monitor changes to `NullSessionPipes` under `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\`.

3. **DLL Load Monitoring (Sysmon Event ID 7):**
   - Alert when `ERAAgent.exe` loads an unsigned `dpapi.dll` from a non-system path.

4. **Hash-Based Detection:**
   - Deploy the known SHA-256 and MD5 hashes to EDR platforms and file integrity monitoring systems.

5. **YARA Scanning:**
   - Deploy the provided YARA rules for periodic filesystem scans of systems running ESET Management Agent.

6. **PowerShell Host Scanner:**
   - Researcher Reichel has published a PowerShell scanner that checks for suspicious registry values, unexpected DLL placement, and static AES encryption keys. Deploy in environments at risk.

### Remediation Steps

1. **Isolate** affected systems from the network immediately upon detection.
2. **Preserve** the malicious DLL for forensic analysis before removal.
3. **Remove** the malicious `dpapi.dll`/`dpapisvc.dll` from the ERAAgent installation directory.
4. **Restore** registry values:
   - Set `EveryoneIncludesAnonymous` to `0`.
   - Remove unauthorized entries from `NullSessionPipes`.
5. **Restart** the ESET Management Agent service to load the legitimate system `dpapi.dll`.
6. **Scan** for lateral movement indicators -- check other systems for the same DLL placement and registry modifications.
7. **Rotate** credentials, particularly any that may have been exposed via the SMB named-pipe transport.
8. **Monitor** for re-compromise, as the operator may attempt to re-establish access through alternate vectors.

---

## Detection Rules

### Sigma Rules

Three Sigma rules are provided at `rules/sigma/`:

<!-- audit: sigma check passed (0 errors, 0 condition errors, 0 issues) with tag validators excluded due to network restriction on MITRE ATT&CK data fetch. sigma convert --without-pipeline -t splunk and -t log_scale succeeded for all three rules, confirming parse validity. Registry rule re-validated after condition change (selection_nullpipes removed, condition now selection_anon only, level medium). -->

**1. `sleepwalker-sideload.yml` -- DLL Side-Loading Detection**

Detects `dpapi.dll` or `dpapisvc.dll` loaded by `ERAAgent.exe` from a non-system directory. Caveat: requires Sysmon Event ID 7 (image load) logging enabled.

- Compile status: PASS (sigma check + sigma convert)
- Confidence: HIGH (direct IOC match on process + DLL name + path exclusion)

**2. `sleepwalker-registry.yml` -- Registry Modification Detection**

Detects `EveryoneIncludesAnonymous` set to 1 (the standalone `NullSessionPipes` selection was removed as overly broad). Caveat: may fire on legacy applications that legitimately require anonymous access (uncommon on modern Windows).

- Compile status: PASS (sigma check + sigma convert --without-pipeline -t splunk + -t log_scale)
- Confidence: LOW (registry indicator is associated with SLEEPWALKER but not unique to this malware; level downgraded to medium)

**3. `sleepwalker-dllload.yml` -- Unsigned DLL Load by ERAAgent**

Higher-fidelity rule targeting `ERAAgent.exe` loading an unsigned `dpapi.dll` from outside system directories. Caveat: requires the `Signed` field populated in image load events (Sysmon with signature validation or equivalent EDR telemetry).

- Compile status: PASS (sigma check + sigma convert)
- Confidence: HIGH (combines process name + DLL name + unsigned status + path exclusion)

### YARA Rules

One YARA file with two rules at `rules/yara/2026-08-31-sleepwalker-backdoor.yar`:

<!-- audit: yarac compiled successfully with no warnings. Requires YARA with pe and hash modules (standard in YARA >= 4.x). -->

**1. `SLEEPWALKER_Backdoor_Hash` -- Hash-Based Detection**

Matches the known SHA-256 hash of the SLEEPWALKER DLL. No false positives possible with hash matching.

- Compile status: PASS (yarac)
- Confidence: HIGH (exact hash match; zero false-positive rate but evaded by any recompilation)

**2. `SLEEPWALKER_Backdoor_DLL_Masquerade` -- Behavioral DLL Detection**

Detects a PE DLL of exactly 59,904 bytes with 7+ exports and dpapi-related strings. Caveat: the exact file size constraint makes this brittle against recompiled variants; it is tuned for the known sample.

- Compile status: PASS (yarac)
- Confidence: HIGH (multiple constraints reduce false positives, but the exact-size check limits detection of variants)

### Network Rules (Snort / Suricata)

**N/A.** SLEEPWALKER contains no fixed network infrastructure (no domains, IPs, or URLs) and uses encrypted activation packets. Traditional network signature rules cannot reliably detect this threat. Detection must rely on host-based indicators described above.

---

## Sources

- [The Hacker News -- Newly Discovered SLEEPWALKER Backdoor Waits for Crafted Network Packet](https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html) (Aug 26, 2026) -- includes researcher Reichel's YARA rules and PowerShell host scanner
- [MITRE ATT&CK Framework](https://attack.mitre.org/) -- Technique mappings

---

*This report was generated in DRAFT mode. All detection rules are PoC/advisory-grade and should be validated in target SIEM/EDR environments before production deployment. The IOCs and analysis are based solely on the cited public source.*
