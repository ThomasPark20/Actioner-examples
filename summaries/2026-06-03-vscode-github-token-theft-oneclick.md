# Technical Analysis Report: VS Code / github.dev "One-Click" GitHub Token Theft (2026-06-03)

Prepared by: Actioner (CTI / Detection Engineering)
Classification: TLP:CLEAR
Date: 2026-06-03
Version: 1.1 (FINAL)

## Executive Summary

Security researcher **Ammar Askar** publicly disclosed (3 Jun 2026) a zero-day in the browser-based VS Code editor **github.dev** that lets an attacker steal a victim's GitHub OAuth token with a single click on a malicious link. The flaw chains two weaknesses: (1) VS Code's webview message-passing bridge forwards `did-keydown` events from a sandboxed webview iframe to the main workbench **without validating the message source**, allowing untrusted webview script to synthesize arbitrary keyboard shortcuts; and (2) **local workspace extensions** (`.vscode/extensions/`) in the web editor can install another extension with a `skipPublisherTrust` context flag, bypassing publisher-trust prompts. A victim who opens an attacker's repo (delivered as a Jupyter notebook with an HTML `onerror` payload) on github.dev has a malicious extension silently installed, which reads the editor's GitHub OAuth session and enumerates the victim's private repositories.

The stolen token is **not scoped** to the repo the victim interacted with — Askar states it has "full access to every other repo that you have access to," including private repositories. The disclosure includes a **public PoC** repo and a full technical writeup. Microsoft tracked the webview-keystroke root cause as VS Code issue #319593 (fixed via PR #319704, milestone 1.124.0). No CVE was assigned at disclosure time. **Important detection caveat:** in the PoC the stolen token is *displayed to the victim in an information box*, not exfiltrated to an attacker-controlled host — so there is no attacker C2/exfil domain to detect. Viable detection keys on the on-disk PoC artifacts (the malicious workspace extension manifest and the notebook keystroke-injection payload), not network indicators.

## Background: github.dev and VS Code Webviews

`github.dev` is GitHub's browser-hosted VS Code editor (press `.` on any repo). It authenticates the user by having `github.com` POST an OAuth token to `github.dev`, which the editor then uses to act on the user's behalf via the GitHub API. The editor renders rich content (notebooks, markdown previews, extension UIs) inside sandboxed **webview** iframes served from a `vscode-webview://` origin, while the main workbench runs at `vscode-file://`. Webviews communicate with the workbench through a `postMessage` bridge. The bug is that the workbench's `did-keydown` handler trusts keyboard events relayed from the webview, so a webview that runs script (XSS, or by design — notebooks/markdown allow embedded HTML) can drive the workbench keyboard as if the user were typing.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-03 | Ammar Askar publishes full disclosure (blog + PoC repo) |
| 2026-06-03 | BleepingComputer and SecurityOnline report the zero-day |
| (pre-disclosure) | Microsoft VS Code issue #319593 filed; fixed via PR #319704 (milestone 1.124.0, VS Code Insiders) |

## Root Cause: Unvalidated webview did-keydown + skipPublisherTrust install

VS Code's webview bridge forwards keyboard events with `hostMessaging.postMessage('did-keydown', { key, keyCode, code, shiftKey, altKey, ctrlKey, metaKey, repeat })` from the sandboxed iframe to the main window, and the workbench dispatches them to its keybinding service without confirming the event originated from genuine user input. A malicious webview can therefore synthesize shortcuts that drive the command palette and other workbench commands. Combined with the web editor accepting a **local workspace extension** whose keybinding invokes `workbench.extensions.installExtension` with `context.skipPublisherTrust: true`, this turns a single click on a hostile repo into silent installation of an arbitrary (token-stealing) extension. Askar notes local workspace extensions "probably weren't well tested with the web version of VSCode."

## Technical Analysis of the Malicious Payload

### 1. Delivery — Malicious notebook webview payload

The PoC is delivered as a Jupyter notebook (`README.ipynb`) opened on github.dev. A markdown/HTML cell carries an image with an `onerror` handler that runs JavaScript inside the webview:

```html
<img src="data:foobar" onerror='/* keystroke-injection payload */'>
```

The payload uses a `window.secondRun` guard to avoid double-execution, waits ~10 seconds for VS Code's "recommended extension" notification, then synthesizes keystrokes against the workbench:

```javascript
window.dispatchEvent(new KeyboardEvent("keydown",
  {key: "a", code: "KeyA", keyCode: 65, ctrlKey: true, shiftKey: true}))  // Ctrl+Shift+A
// ...then after ~500ms: Ctrl+F1 (keyCode 112)
```

`Ctrl+Shift+A` accepts the workspace-extension-recommendation notification; `Ctrl+F1` triggers the malicious extension's keybinding.

### 2. Stage — Malicious local workspace extension

The repo ships a local workspace extension at `.vscode/extensions/my-extension/` whose `package.json` (`name: token-steal-poc`, `publisher: Ammar`) binds `ctrl+f1` to a `runCommands` chain that silently installs the second-stage extension:

```json
{ "key": "ctrl+f1", "command": "runCommands",
  "args": { "commands": [
    { "command": "workbench.extensions.installExtension",
      "args": ["AmmarTest.hello-ammar-github",
               { "donotSync": true, "context": { "skipPublisherTrust": true } }] }
  ] } }
```

`skipPublisherTrust: true` suppresses the publisher-trust dialog in a trusted workspace.

### 3. C2 Infrastructure

**None in the PoC.** The second-stage extension (`AmmarTest.hello-ammar-github`) reads the editor's GitHub OAuth session and calls the legitimate GitHub API endpoint `https://api.github.com/user/repos` to enumerate private repos, then **displays the token and repo list to the victim in an information box** to prove impact. There is **no attacker-controlled exfiltration domain, URL, or beacon** — a weaponized variant would add one, but none exists in the published artifacts. This is why no network detection is offered (see Detection Rules).

### 4. Platform-Specific Behavior

The bug is in the **web** build of VS Code (github.dev / vscode.dev). The desktop client is less directly affected because local workspace extensions and the github.dev OAuth-token POST flow are specific to the hosted browser editor. Detection artifacts (the workspace extension manifest, the notebook payload) live in the **repository tree on disk** and are platform-agnostic at the file level.

### 5. Anti-Forensics / Evasion Techniques

Minimal: the `window.secondRun` guard prevents re-firing; the ~10s delay waits for the recommendation toast. The attack relies on the victim having a live github.dev session so the OAuth token is already present (no sign-in prompt is shown).

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs use `hxxps://`, dots `[.]`, `@` -> `[at]`.

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `token-steal-poc` (publisher `Ammar`) | 0.0.1 | Local workspace extension; keybinding silently installs the second stage |
| `AmmarTest.hello-ammar-github` | n/a | Second-stage extension that reads the OAuth session and queries the GitHub API |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Any | `.vscode/extensions/my-extension/package.json` | n/a (no hash published) | Malicious workspace extension manifest with `skipPublisherTrust` install keybinding |
| Any | `README.ipynb` (PoC repo) | n/a | Notebook carrying the `onerror` keystroke-injection payload |

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `github[.]dev` | Vulnerable hosted editor; receives the OAuth token POST from github.com (legitimate infra, not an IOC) |
| URL | `hxxps://api[.]github[.]com/user/repos` | Endpoint the second-stage extension calls (legitimate GitHub API — not a usable network IOC) |
| URL | `hxxps://github[.]dev/ammaraskar/github-dev-token-steal-poc/blob/main/README[.]ipynb` | PoC entry-point link |

> No attacker-controlled exfiltration infrastructure exists in the PoC; the above are legitimate-but-abused endpoints, not blockable IOCs.

### Behavioral

A webview/notebook iframe dispatching synthetic `KeyboardEvent("keydown")` events (Ctrl+Shift+A then Ctrl+F1) into the workbench; a local workspace extension keybinding invoking `workbench.extensions.installExtension` with `context.skipPublisherTrust: true`; a `.vscode/extensions/*/package.json` appearing in a freshly opened/cloned repository.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1204.001 | User Execution: Malicious Link | Victim clicks a link to a hostile github.dev repo/notebook |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Webview `onerror` JS synthesizes keystrokes into the workbench |
| T1176 | Software Extensions | Malicious local workspace extension auto-installs a second-stage VS Code extension |
| T1528 | Steal Application Access Token | Second-stage extension reads the github.dev GitHub OAuth session token |
| T1213.003 | Data from Information Repositories: Code Repositories | Token enumerates and accesses the victim's private GitHub repos |

## Impact Assessment

High severity for any user with a live github.dev session: a single click yields a full-scope GitHub OAuth token covering **all** repositories the victim can access, including private code. Breadth is limited by requiring the victim to (a) already be authenticated to github.dev and (b) open the attacker's repo in the web editor, but those are low-friction prerequisites given how github.dev is promoted (press `.` on any repo). Stealth is high pre-disclosure — no sign-in prompt and no obvious UI beyond a brief recommended-extension toast.

## Detection & Remediation

### Immediate Detection

- Inspect any repository opened in github.dev/vscode.dev for a `.vscode/extensions/*/package.json` containing `skipPublisherTrust` and/or `workbench.extensions.installExtension` in a keybinding — these are not normal in legitimate repos.
- Search notebooks/markdown for embedded `<img ... onerror=...>` handlers that call `new KeyboardEvent("keydown", ...)`.
- Review installed VS Code (web) extensions for unexpected publishers (e.g. the PoC's `AmmarTest.hello-ammar-github`).

### Remediation

1. **Containment:** Clear cookies and site/application storage for `github.dev` in the browser; this forces a fresh GitHub sign-in dialog and prevents silent token reuse (Askar's recommended interim mitigation).
2. **Eradication:** Remove any unexpected web-editor extensions; do not open untrusted repos in github.dev/vscode.dev until patched.
3. **Recovery / secret rotation:** If a session may have been exposed, **revoke active GitHub OAuth sessions/tokens and re-authorize**, and audit recent private-repo access.
4. Apply VS Code 1.124.0+ (fixes the `did-keydown` webview-keystroke root cause, PR #319704).

> The "clear github.dev storage" step is an interim mitigation, not a fix — its efficacy depends on the browser re-prompting for sign-in. The durable fix is the VS Code patch.

### Long-Term Hardening

Treat web-based editors as token-bearing browser contexts: prefer fine-grained, repo-scoped tokens over full-scope OAuth sessions; disable or sandbox local workspace extensions in hosted editors; and validate the source/origin of all webview->workbench messages.

## Detection Rules

These detections target the on-disk artifacts of the PoC, since the bug is a client-side/browser token-exfil with no attacker network infrastructure. The YARA rule fires on the two distinctive published artifacts (the malicious workspace extension manifest and the notebook keystroke-injection payload); the Sigma rule flags a local workspace extension manifest being written under `.vscode/extensions/` (an unusual, attacker-controllable artifact). No Snort/Suricata rules: the only network traffic is legitimate `github.dev`/`api.github.com` flows, so a network rule would be pure noise. Note: compiles/fires here is not a substitute for tuning in your environment.

### Sigma: Malicious VS Code Local Workspace Extension Manifest Written to Disk
Flags a `package.json` created under a repo's `.vscode/extensions/` directory — the on-disk landing spot of the auto-installing token-theft extension. Hunt-oriented: pair with the YARA content check, since file_event rarely carries file content.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: tags T1554->T1176 (Software Extensions); prose trimmed to 2 sentences, FP/triage detail moved here. -->
<!-- audit: sigma check 0; splunk 0; log_scale 0. No sysmon pipeline installed in toolchain -> schema-map (2) skipped; TargetFilename is a standard Sysmon EID 11 field. Path keyed both \\ (Windows) and / (nix/web-sync). Broad by design (matches any local workspace extension manifest) -> medium, not high; pair with YARA content check or manual triage of manifests for skipPublisherTrust/installExtension; scope to dev endpoints. tags: T1204.001 malicious link, T1528 steal app access token, T1176 software extensions. FP: legit committed workspace extensions in monorepos; developers distributing a workspace-scoped extension. -->
```yaml
title: Malicious VS Code Local Workspace Extension Manifest Written to Disk
id: 480bde3f-10f3-4275-b18a-dae14b8dee40
status: experimental
description: >
    Detects a VS Code/Code-OSS local workspace extension manifest (package.json)
    being created under a repository's .vscode/extensions directory. This is the
    on-disk artifact of the github.dev "one-click" GitHub token theft, where a
    cloned/opened repo ships a local workspace extension whose keybinding silently
    runs workbench.extensions.installExtension with skipPublisherTrust to load a
    token-stealing extension. Local workspace extensions execute with repo trust
    and are an unusual, attacker-controllable artifact in a checked-out tree.
references:
    - https://blog.ammaraskar.com/github-token-stealing/
    - https://github.com/microsoft/vscode/issues/319593
    - https://www.bleepingcomputer.com/news/security/vs-code-zero-day-lets-hackers-steal-github-tokens-in-one-click/
author: Actioner
date: 2026-06-03
tags:
    - attack.t1204.001
    - attack.t1528
    - attack.t1176
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|contains: '\.vscode\extensions\'
        TargetFilename|endswith: '\package.json'
    selection_nix:
        TargetFilename|contains: '/.vscode/extensions/'
        TargetFilename|endswith: '/package.json'
    condition: selection or selection_nix
falsepositives:
    - Legitimately committed local workspace extensions in a trusted monorepo
    - Developers intentionally distributing a workspace-scoped extension
level: medium
```

### Snort: N/A
Only legitimate `github.dev`/`api.github.com` TLS traffic is involved; the PoC has no attacker exfil host. A network rule would be false-positive noise.

### Suricata: N/A
Same as Snort — no attacker-controlled network indicator to key on.

### YARA: github.dev One-Click Token-Theft PoC Artifacts
Fires on the malicious workspace extension manifest (`installExtension` + `skipPublisherTrust` + the PoC extension ID) or the notebook keystroke-injection payload (`KeyboardEvent("keydown")` with the Ctrl+Shift+A/Ctrl+F1 combo and `secondRun`/`data:foobar` markers).
**Status:** compile ✅ compiles · confidence: high · sample: fired ✓
<!-- audit: yarac exit 0. Sample-tested: grounded positive #1 = published extension package.json (installExtension+skipPublisherTrust+AmmarTest.hello-ammar-github) -> MATCH; grounded positive #2 = published notebook onerror payload (KeyboardEvent keydown, ctrlKey/shiftKey, secondRun, data:foobar) -> MATCH; benign negative = esbenp.prettier-vscode manifest -> no match. Positives drawn from researcher's published blog/PoC, not invented. filesize<200KB scopes to manifests/notebook cells. High confidence: keys on multi-token combinations (skipPublisherTrust + installExtension) and PoC-specific IDs unlikely in benign files; a re-skinned variant changing the extension ID/strings would evade -> behavioral Sigma backstops. -->
```yara
rule Exploit_VSCode_GithubDev_Token_Theft_OneClick
{
    meta:
        description = "Detects the github.dev one-click GitHub token theft PoC artifacts: a malicious workspace .vscode extension that maps a keybinding to workbench.extensions.installExtension with skipPublisherTrust, and/or the notebook webview payload that synthesizes did-keydown events to silently install the second-stage extension"
        author = "Actioner"
        date = "2026-06-03"
        reference = "https://blog.ammaraskar.com/github-token-stealing/"
        tlp = "WHITE"
        severity = "high"

    strings:
        // --- Malicious workspace extension manifest (.vscode/extensions/*/package.json) ---
        $m_install   = "workbench.extensions.installExtension" ascii
        $m_skiptrust = "skipPublisherTrust" ascii
        $m_target    = "AmmarTest.hello-ammar-github" ascii
        $m_runcmds   = "runCommands" ascii
        $m_keybind   = "ctrl+f1" ascii nocase

        // --- Malicious notebook / webview payload (did-keydown injection) ---
        $p_imgerr    = "onerror=" ascii nocase
        $p_kbevent   = "new KeyboardEvent" ascii
        $p_keydown   = "\"keydown\"" ascii
        $p_secondrun = "secondRun" ascii
        $p_combo     = "ctrlKey: true, shiftKey: true" ascii
        $p_dataimg   = "data:foobar" ascii

    condition:
        filesize < 200KB and
        (
            ($m_install and $m_skiptrust and ($m_target or $m_runcmds or $m_keybind))
            or
            ($p_kbevent and $p_keydown and ($p_secondrun or $p_combo or $p_dataimg))
            or
            ($p_imgerr and $p_dataimg and $p_kbevent)
        )
}
```

## Lessons Learned

Browser-hosted code editors hold full-scope OAuth tokens in a sandbox that also renders attacker-influenced content (notebooks, markdown, webviews). Any gap that lets sandboxed content drive trusted UI (here, unvalidated `did-keydown` messages plus a `skipPublisherTrust` install path) collapses the boundary between "viewing a repo" and "running code with the user's credentials." Defenses must treat such editors like browsers: minimize token scope, validate every cross-context message origin, and never let untrusted workspace content silently install extensions.

## Sources

- [BleepingComputer — VS Code zero-day lets hackers steal GitHub tokens in one click](https://www.bleepingcomputer.com/news/security/vs-code-zero-day-lets-hackers-steal-github-tokens-in-one-click/) — news report confirming researcher, mechanism, and links to primary sources
- [SecurityOnline — GitHub token-stealing bug in VS Code](https://securityonline.info/github-token-stealing-bug-vscode/) — secondary report on the disclosure and root cause
- [Ammar Askar — GitHub token stealing (primary writeup)](https://blog.ammaraskar.com/github-token-stealing/) — researcher's full technical disclosure, payload and manifest details
- [PoC repository — ammaraskar/github-dev-token-steal-poc](https://github.com/ammaraskar/github-dev-token-steal-poc/) — published proof-of-concept (notebook payload + workspace extension)
- [Microsoft VS Code issue #319593](https://github.com/microsoft/vscode/issues/319593) — webview did-keydown root cause; fixed via PR #319704 (milestone 1.124.0)

---
*Report generated by Actioner*
