# Technical Analysis Report: Cursor IDE Unpatched RCE via Malicious git.exe (2026-07-16)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-07-16
Version: 1.0 (DRAFT)

## Executive Summary

An unpatched zero-day vulnerability in the Cursor AI code editor (7+ million active users) allows arbitrary code execution on Windows when a developer opens a repository containing a malicious `git.exe` in the project root. Cursor's Git binary path resolution logic searches the workspace directory and executes any `git.exe` found there automatically -- without user consent, approval dialogs, or any visible indication. The vulnerability was discovered by Aaron Portnoy of Mindgard and reported to Cursor on December 15, 2025. After seven months and 197+ Cursor releases with no patch or substantive vendor response, Mindgard published full disclosure on July 14, 2026. No CVE has been assigned. The attack requires no exploit chain, prompt injection, or sophisticated tradecraft -- an attacker simply places a trojanized binary named `git.exe` in a repository root. The vulnerability has been confirmed present through Cursor 3.11 (July 10, 2026).

## Background: Cursor AI Code Editor

Cursor is one of the most widely adopted AI-assisted code editors, built as a fork of Visual Studio Code. It claims over 7 million active users, more than 1 million daily active users, over 1 million paying subscribers, and adoption across more than 50,000 companies. Cursor integrates AI-powered code completion, editing, and chat features on top of the VS Code foundation. Like VS Code, Cursor relies on Git for source control operations and searches for Git binaries during project initialization. The vulnerability is specific to Windows, where executable resolution follows the `PATH` and working-directory search order.

Notably, this class of vulnerability is not unique to Cursor. A June 2026 Cymulate report identified similar Git binary resolution issues in GitHub Copilot CLI, Google Gemini CLI, and OpenAI Codex -- all of which executed workspace-local `git.exe` before or during trust prompts. VS Code itself has documented workspace-local binary resolution behavior, though it implements a Workspace Trust feature that Cursor lacks.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2025-12-15 | Mindgard discovers vulnerability and reports to security-reports@cursor.com |
| 2026-01 (mid) | Cursor CISO acknowledges automation failure; invites Mindgard to HackerOne |
| 2026-01-16 | HackerOne report initially closed as out-of-scope; reopened after reproduction |
| 2026-01-20 to 2026-06-01 | Multiple follow-up status requests by Mindgard go unanswered |
| 2026-04-30 | Mindgard confirms vulnerability persists in Cursor 3.2.16 via Process Monitor |
| 2026-07-10 | Cursor 3.11 tested and confirmed still vulnerable |
| 2026-07-14 | Mindgard publishes full disclosure |
| 2026-07-15 | SecurityWeek, The Hacker News, Dark Reading publish coverage |

## Root Cause: Git Binary Path Resolution in Workspace Directory

When Cursor opens a project, it invokes Git for source control operations (e.g., `git rev-parse --show-toplevel` to determine the repository root). The binary search logic includes the current workspace/project root directory as one of the candidate paths. On Windows, if a file named `git.exe` exists in the project root, Cursor resolves and executes it instead of the legitimate Git installation. There is no trust prompt, sandboxing, or signature verification before execution. The binary runs with the full privileges of the logged-in user.

This is a classic instance of DLL/binary search-order hijacking applied to the IDE workspace context. The root cause is the failure to restrict Git binary resolution to known-safe installation directories (e.g., `%ProgramFiles%\Git\`, `%LOCALAPPDATA%\Programs\Git\`).

## Technical Analysis of the Malicious Payload

### 1. Attack Delivery -- Poisoned Repository

The attack vector is straightforward: an attacker creates a Git repository containing a malicious executable named `git.exe` at the project root. This repository is distributed via any standard mechanism -- GitHub, GitLab, direct clone URL, or shared archive. Since cloning a repository is the normal way binaries land on disk in development workflows, this bypasses the usual suspicion associated with downloading executables.

Additional binary names at risk include `npx.exe`, `node.exe`, and `where.exe`, which may also be resolved from workspace directories by Cursor or related tooling.

### 2. Execution -- Automatic Binary Hijack on Project Load

When the developer opens the poisoned repository in Cursor:

1. Cursor initiates Git operations as part of project load
2. The path resolution logic finds `git.exe` in the workspace root
3. Cursor spawns the malicious binary, passing Git arguments (e.g., `rev-parse --show-toplevel`)
4. The binary executes with user-level privileges
5. Execution recurs during normal IDE operation (not just once at load)

Process Monitor evidence from the Mindgard PoC (Cursor 3.2.16, April 30, 2026):
- **Parent process:** `Cursor.exe` (PID 54880)
- **Child process:** `git.exe` (from project root, not Program Files)
- **Command line:** `git rev-parse --show-toplevel`

The PoC used the Windows Calculator (`calc.exe`) renamed to `git.exe`. Multiple Calculator instances launched automatically and repeatedly while the project was open, demonstrating sustained code execution without any user interaction.

### 3. C2 Infrastructure

No C2 infrastructure is associated with the PoC or disclosure. In a weaponized scenario, the malicious `git.exe` would function as a first-stage loader executing under the developer's privileges with access to source code, SSH keys, cloud tokens, and development credentials.

### 4. Platform-Specific Behavior

#### Windows

This is the only confirmed affected platform. The vulnerability depends on Windows executable search-order behavior where the current directory is included in binary resolution. The malicious binary must be named `git.exe` (or another tool name that Cursor resolves).

#### macOS / Linux

Not confirmed affected. Unix systems typically do not include the current directory in `PATH` by default, and the binary would need to be named `git` (no extension). However, the underlying path resolution logic in Cursor should be independently verified on these platforms.

### 5. Anti-Forensics / Evasion Techniques

The attack has inherent evasion properties:
- **No exploit chain required** -- the binary is executed through legitimate IDE functionality
- **Blends with normal development workflow** -- cloning repositories is expected behavior
- **Signed parent process** -- Cursor.exe is a legitimate, signed application, making the parent-child relationship appear benign in some EDR configurations
- **Persistence through project use** -- the binary re-executes during normal IDE operation, not just at initial load

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://` (e.g., `hxxps://evil[.]com/payload`)
> - Domains: `[.]` replacing dots (e.g., `evil[.]com`)
> - IP addresses: `[.]` replacing dots (e.g., `1.2.3[.]4`)
> - Email addresses: `[at]` replacing @ (e.g., `attacker[at]evil[.]com`)

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| Cursor IDE | All through 3.11 (2026-07-10) | Vulnerable Git binary resolution logic |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Windows | `<repo_root>\git.exe` | Varies (attacker-supplied) | Malicious binary masquerading as Git |
| Windows | `<repo_root>\npx.exe` | Varies (attacker-supplied) | Potential additional hijack target |
| Windows | `<repo_root>\node.exe` | Varies (attacker-supplied) | Potential additional hijack target |
| Windows | `<repo_root>\where.exe` | Varies (attacker-supplied) | Potential additional hijack target |

### Network

No network IOCs -- this is a local binary execution vulnerability. Network indicators would depend on the attacker's payload.

### Behavioral

- `Cursor.exe` spawning `git.exe` from a path that is NOT a standard Git installation directory (e.g., not under `Program Files\Git\`, `AppData\Local\Programs\Git\`)
- `git.exe` present in a repository root directory (file named `git.exe` at the top level of a Git working tree)
- Multiple rapid process creation events of `git.exe` from a project directory during Cursor session
- Command line pattern: `git rev-parse --show-toplevel` executed from a non-standard Git path

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.002 | User Execution: Malicious File | Developer opens poisoned repository in Cursor, triggering automatic execution of malicious git.exe |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Malicious binary named git.exe to match the legitimate Git executable |
| T1574.008 | Hijack Execution Flow: Path Interception by Search Order Hijacking | Cursor resolves git.exe from workspace root before legitimate Git installation paths |
| T1059 | Command and Scripting Interpreter | Arbitrary code execution achieved through the hijacked binary |

## Impact Assessment

- **Breadth:** 7+ million active Cursor users on Windows are potentially affected. Over 50,000 companies use Cursor.
- **Depth:** Full arbitrary code execution under the developer's user context. Access to source code, SSH keys, cloud credentials, API tokens, and development secrets.
- **Stealth:** High. The attack leverages normal IDE behavior with no visible indicators to the user. No prompts, no dialogs, no warnings.
- **Exposure window:** At least 7 months (December 2025 to July 2026 and counting). 197+ Cursor versions released without a fix.
- **No CVE assigned.** Cursor has published no security advisory.

## Detection & Remediation

### Immediate Detection

Scan cloned repositories for suspicious executables in the project root before opening in Cursor:

```powershell
# PowerShell: Check for suspicious binaries in a repo root before opening
$suspiciousBinaries = @('git.exe', 'npx.exe', 'node.exe', 'where.exe')
$repoRoot = "C:\path\to\cloned\repo"
$suspiciousBinaries | ForEach-Object {
    $path = Join-Path $repoRoot $_
    if (Test-Path $path) {
        Write-Warning "SUSPICIOUS: Found $_ in repository root: $path"
        Get-FileHash $path -Algorithm SHA256
    }
}
```

Query EDR/SIEM for Cursor spawning git.exe from non-standard paths:

```
# Splunk query
index=sysmon EventCode=1 ParentImage="*\\Cursor.exe" Image="*\\git.exe"
NOT (Image="*\\Program Files\\Git\\*" OR Image="*\\Program Files (x86)\\Git\\*" OR Image="*\\AppData\\Local\\Programs\\Git\\*")
```

### Remediation

1. **Immediate:** Open untrusted repositories only in isolated environments (Windows Sandbox, disposable VMs, containers)
2. **Enterprise:** Deploy AppLocker or Windows Defender Application Control (WDAC) deny rules blocking executable names (`git.exe`, `npx.exe`, `node.exe`, `where.exe`) from workspace root directories
   - Example AppLocker path rule: `%USERPROFILE%\source\repos\*\git.exe` (DENY)
   - Use path-based deny rules, not hash-based (attacker-supplied binaries vary by hash)
3. **Pre-clone scanning:** Implement CI/CD or hook-based scanning to check for executables in repository roots before developer interaction
4. **Monitor:** Deploy the Sigma detection rules below to alert on suspicious process creation patterns

### Long-Term Hardening

- **IDE vendors:** Restrict Git binary resolution to explicit, known-safe installation paths. Implement workspace trust models (similar to VS Code's Workspace Trust) that prompt before executing workspace-local binaries.
- **Developers:** Audit `.gitignore` patterns to ensure executable files are not committed to repositories. Use pre-commit hooks to reject binaries at repository root.
- **Enterprises:** Enforce application whitelisting policies that restrict executable paths in developer workspace directories. Consider EDR parent-process-aware rules that flag IDE processes spawning binaries from project directories.

## Detection Rules

Two Sigma rules target the specific Cursor git.exe hijack vector and the broader workspace-binary-hijack pattern. Both convert cleanly to Splunk and CrowdStrike LogScale. No network indicators exist for Snort/Suricata rules, and no file-level signature artifacts exist for YARA (the malicious binary is attacker-supplied and varies).

### Sigma: Cursor IDE Executing Git Binary From Project Directory

Detects Cursor.exe spawning git.exe from a path outside standard Git installation directories -- the specific exploitation vector for this 0-day.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check blocked by MITRE ATT&CK fetch (proxy 403, non-rule issue); splunk convert exit 0; log_scale convert exit 0; splunk_windows pipeline convert exit 0. Fields: ParentImage, Image — standard Sysmon/process_creation. Filter covers Program Files, AppData, usr/bin, mingw paths. FP: portable Git in non-standard paths (uncommon on managed endpoints). Evasion: attacker renames Cursor fork or uses different IDE — rule is Cursor-specific by design. -->
```yaml
title: Cursor IDE Executing Git Binary From Project Directory
id: 7c3a91f2-e4b8-4d1a-9f6e-2a5c8b0d3e7f
status: experimental
description: >
    Detects Cursor IDE spawning a git.exe process from a project/workspace
    directory rather than the legitimate Git installation path. This is the
    specific exploitation vector for the unpatched Cursor 0-day where a
    malicious git.exe placed in a repository root is executed automatically
    during project load.
references:
    - https://mindgard.ai/blog/cursor-0day-when-full-disclosure-becomes-the-only-protection-left
    - https://www.securityweek.com/unpatched-cursor-vulnerability-exposes-users-to-code-execution/
author: Actioner
date: 2026/07/16
tags:
    - attack.t1204.002
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\Cursor.exe'
    selection_child:
        Image|endswith: '\git.exe'
    filter_legitimate_git:
        Image|contains:
            - '\Program Files\Git\'
            - '\Program Files (x86)\Git\'
            - '\AppData\Local\Programs\Git\'
            - '\usr\bin\'
            - '\mingw64\bin\'
            - '\mingw32\bin\'
    condition: selection_parent and selection_child and not filter_legitimate_git
falsepositives:
    - Portable Git installations in non-standard paths
    - Custom Git builds used by developers
level: high
```

### Sigma: Suspicious Executable in Repository Root Mimicking Developer Tool

Detects execution of binaries named after common developer tools (git.exe, npx.exe, node.exe, where.exe) from repository/workspace directories -- broader coverage for the workspace binary hijack pattern.
**Status:** compile ✅ compiles · confidence: medium
<!-- audit: sigma check blocked by MITRE ATT&CK fetch (proxy 403, non-rule issue); splunk convert exit 0; log_scale convert exit 0; splunk_windows pipeline convert exit 0. Fields: Image — standard process_creation. selection_path scoped to common workspace roots (source\repos, Documents\GitHub, Projects, repos, workspace). FP: portable node/git in project trees (possible in some dev setups — tune path filters). Broader than rule 1; intended as hunt companion. -->
```yaml
title: Suspicious Executable in Repository Root Mimicking Developer Tool
id: 1d8e5f3a-b7c2-4a96-8e0d-9f4b6c1a2d5e
status: experimental
description: >
    Detects execution of binaries named after common developer tools
    (git.exe, npx.exe, node.exe, where.exe) from repository or workspace
    root directories. Attackers can place trojanized binaries in cloned
    repositories to achieve code execution when an IDE or CLI tool resolves
    them via path search.
references:
    - https://mindgard.ai/blog/cursor-0day-when-full-disclosure-becomes-the-only-protection-left
    - https://www.securityweek.com/unpatched-cursor-vulnerability-exposes-users-to-code-execution/
author: Actioner
date: 2026/07/16
tags:
    - attack.t1204.002
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_name:
        Image|endswith:
            - '\git.exe'
            - '\npx.exe'
            - '\node.exe'
            - '\where.exe'
    selection_path:
        Image|contains:
            - '\source\repos\'
            - '\Documents\GitHub\'
            - '\Projects\'
            - '\repos\'
            - '\workspace\'
    filter_legitimate:
        Image|contains:
            - '\node_modules\.bin\'
            - '\Program Files\'
            - '\Program Files (x86)\'
            - '\AppData\Local\Programs\'
            - '\nvm\'
    condition: selection_name and selection_path and not filter_legitimate
falsepositives:
    - Developers running portable tool installations from within project trees
    - Build scripts that compile and run git/node wrappers locally
level: medium
```

### Snort: N/A

No network-level indicators -- this is a local binary execution vulnerability with no associated C2 infrastructure in the disclosure.

### Suricata: N/A

No network-level indicators suitable for Suricata detection.

### YARA: N/A

No file-level signature artifacts -- the malicious binary is attacker-supplied and varies by payload. A YARA rule matching `git.exe` by name alone would be overbroad.

## Lessons Learned

1. **IDE workspace trust is a security boundary.** VS Code introduced Workspace Trust for exactly this reason -- untrusted repositories should not be able to trigger binary execution. Cursor, despite being a VS Code fork, lacks this protection. AI-assisted IDEs that integrate deeply with developer toolchains inherit the security responsibilities of those toolchains.

2. **Binary search-order hijacking is old, but the attack surface is new.** The technique (T1574.008) dates back decades in Windows security, but the proliferation of AI code editors that aggressively auto-invoke developer tools creates new, high-value exploitation surfaces. The Cymulate report showing the same class of vulnerability in Copilot CLI, Gemini CLI, and Codex demonstrates this is a systemic issue across AI development tools.

3. **Vendor response gaps leave users exposed.** Seven months with no patch, no advisory, and no CVE -- across 197+ releases -- represents a significant failure in vulnerability management. Organizations relying on Cursor should factor vendor security responsiveness into their tool adoption decisions.

4. **Detection before patch.** When a vendor does not produce a patch, endpoint detection (Sigma rules keyed on process creation anomalies) and application control policies (AppLocker/WDAC) become the primary defensive controls. Organizations should deploy the detection rules in this report and enforce path-based execution restrictions on developer workstations.

## Sources

- [Mindgard Blog: Cursor 0day Full Disclosure](https://mindgard.ai/blog/cursor-0day-when-full-disclosure-becomes-the-only-protection-left) -- primary technical disclosure by Aaron Portnoy; includes Process Monitor evidence, PoC details, and full disclosure timeline
- [SecurityWeek: Unpatched Cursor Vulnerability Exposes Users to Code Execution](https://www.securityweek.com/unpatched-cursor-vulnerability-exposes-users-to-code-execution/) -- secondary reporting with vendor context and user impact figures
- [The Hacker News: Cursor Flaw Lets Malicious Cloned Repositories Trigger Windows Code Execution](https://thehackernews.com/2026/07/cursor-flaw-lets-malicious-cloned.html) -- additional technical details, Cursor 3.11 still-vulnerable confirmation, and Cymulate cross-tool comparison

---
*Report generated by Actioner*
