# AutoJack: AutoGen Studio AI Agent RCE via MCP WebSocket Exploitation

**Date:** 2026-06-19
**Status:** FINAL
**TLP:** WHITE
**CVE:** No CVE assigned (vulnerability in development branch only; never shipped to PyPI)
**CWE:** CWE-1385 (Missing Origin Validation in WebSockets), CWE-306 (Missing Authentication for Critical Function), CWE-78 (OS Command Injection)

---

## Executive Summary

Microsoft Defender Security Research disclosed "AutoJack," a three-part vulnerability chain in AutoGen Studio (Microsoft's open-source AI agent prototyping UI) that allows a malicious webpage rendered by an AI browsing agent to achieve remote code execution on the developer's host machine. The exploit chains an origin bypass via agent browsing, an authentication bypass on the MCP WebSocket endpoint (`/api/mcp/ws/`), and unsanitized command execution via base64-encoded `StdioServerParams` passed through a query string parameter. A malicious page's JavaScript opens a WebSocket to `localhost:8081`, passes a crafted payload, and AutoGen Studio spawns arbitrary processes under the developer's account.

The vulnerability existed only in development builds on the AutoGen main branch between the MCP plugin landing and commit b047730. The current PyPI release (autogenstudio 0.4.2.2) was never affected -- the MCP WebSocket route was never included in any published package. The fix, authored by Victor Dibia, moved parameters to server-side session storage, removed `/api/mcp` from the authentication skip list, and added session ID validation (close code 4004 for unknown sessions). The research was led by Shaked Ilan of the Microsoft Defender Security Research Team.

---

## Background: AutoGen Studio and the MCP WebSocket Surface

AutoGen Studio is an open-source prototyping interface for Microsoft's AutoGen multi-agent AI framework. It provides a web-based UI for building, testing, and deploying AI agents, including agents with web-browsing capabilities (MultimodalWebSurfer, fetch_webpage_tool, Playwright-backed browsers). The studio runs as a FastAPI application, typically bound to `localhost:8081` (or `8080`), and exposes a Model Context Protocol (MCP) WebSocket endpoint for managing server connections.

The MCP integration allows agents to connect to external tool servers via `stdio_client()`, which spawns child processes based on `StdioServerParams` configuration. This is the endpoint that was exploited. The localhost trust boundary -- the assumption that services bound to loopback are safe from external interaction -- is the core security model that AutoJack breaks: a browsing agent running locally inherits the localhost identity, allowing attacker-controlled JavaScript to satisfy origin checks.

---

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| Pre-2026-06-18 | MCP WebSocket plugin lands on AutoGen main branch, introducing `/api/mcp/ws/` endpoint |
| Pre-2026-06-18 | Microsoft Defender Security Research identifies the vulnerability chain |
| Pre-2026-06-18 | Vulnerability reported to Microsoft Security Response Center (MSRC) |
| Pre-2026-06-18 | Fix committed as b047730 on AutoGen main branch (pyproject.toml version 0.7.2) |
| 2026-06-18 | Microsoft Security Blog publishes full technical disclosure of AutoJack |

---

## Root Cause: Localhost Trust Boundary Violation via AI Agent Browsing

The exploit abuses the fact that an AI agent with browsing capabilities renders arbitrary web content in a local browser context. Since the browser runs on localhost, any JavaScript on a rendered page can open connections to other localhost services, bypassing origin restrictions that would block connections from remote origins. The attacker does not need direct network access to the developer's machine -- the browsing agent acts as a last-mile delivery vehicle.

---

## Technical Analysis of the Malicious Payload

### 1. Origin Bypass via Agent Browsing

The AutoGen Studio origin check validated only that the connecting origin was `http://127.0.0.1` or `http://localhost`. Because the AI browsing agent (MultimodalWebSurfer, Playwright-based) renders attacker content in a local browser, JavaScript on the attacker's page inherits the localhost origin. The attacker plants malicious content on any webpage the agent might visit -- either through direct luring, SEO poisoning, or indirect prompt injection.

### 2. Authentication Bypass on MCP WebSocket

The FastAPI authentication middleware explicitly skipped all paths starting with `/api/mcp` and `/api/ws`:

```python
if request.url.path.startswith("/api/ws") or request.url.path.startswith("/api/mcp"):
    return await call_next(request)
```

This bypass applied regardless of the configured authentication mode (none, GitHub, MSAL, Firebase). The MCP WebSocket handler itself performed no authentication checks, leaving the endpoint fully unauthenticated.

### 3. Arbitrary Command Execution via StdioServerParams

The WebSocket handler decoded base64-encoded JSON from the `server_params` query parameter and passed it directly to process spawning:

```python
@router.websocket("/ws/{session_id}")
async def mcp_websocket(websocket: WebSocket, session_id: str):
    encoded = websocket.query_params.get("server_params")
    decoded = base64.b64decode(encoded)
    params = StdioServerParams(**json.loads(decoded))
    await create_mcp_session(bridge, params, session_id)
```

No allowlisting of executables was performed. The attacker could specify any command in the `command` field of the JSON payload:

```json
{
  "type": "StdioServerParams",
  "command": "calc.exe",
  "args": [],
  "env": { "pwned": "true" }
}
```

The full exploit URL: `ws://localhost:8081/api/mcp/ws/?server_params=<base64-encoded-JSON>`

### 4. Realistic Attack Scenario

1. Developer builds a web content summarizer agent using MultimodalWebSurfer
2. Attacker plants malicious JavaScript on a legitimate site (or via prompt injection)
3. Agent's browsing tool navigates to the attacker-controlled page
4. Page JavaScript opens WebSocket: `ws://localhost:8081/api/mcp/ws/?server_params=<base64>`
5. AutoGen Studio decodes payload and executes arbitrary command under the developer's account

### 5. Fix Applied (Commit b047730)

The fix by Victor Dibia (PR #7362) implemented three hardening measures:

1. **Server-side parameter binding:** A separate `POST /api/mcp/ws/connect` endpoint stores parameters server-side in `pending_session_params`, keyed by UUID. The WebSocket handler refuses unknown session IDs with close code 4004.
2. **Authentication enforcement:** Removed `/api/mcp` from the middleware skip list. Only `/api/ws` and `/api/maker` remain exempt; MCP routes now flow through normal authentication.
3. **FunctionTool deprecation:** Removed `FunctionTool._from_config()` which used `exec()` on user-provided `source_code`, an additional RCE vector.

---

## Indicators of Compromise (IOCs)

> **Defanging Convention:** External IOCs use defanged notation: URLs `hxxps://`, domains `[.]`, IPs `[.]`, emails `[at]`. Localhost/loopback URLs are not defanged as they are non-routable and specific to the exploit pattern.

### Package / Software Level

| Package / Component | Vulnerable Version | Description |
|---------------------|-------------------|-------------|
| autogenstudio (GitHub main) | Between MCP plugin landing and commit b047730 | MCP WebSocket endpoint with unsanitized command execution |
| autogenstudio (PyPI) | 0.4.2.2 (NOT affected) | PyPI release never included the vulnerable MCP WebSocket route |

### Network

| Type | Value | Context |
|------|-------|---------|
| URL Pattern | `ws://localhost:8081/api/mcp/ws/?server_params=` | Exploit WebSocket connection URL (localhost not defanged — loopback only) |
| URL Pattern | `ws://localhost:8080/api/mcp/ws/?server_params=` | Alternate port exploit URL (localhost not defanged — loopback only) |
| Endpoint | `/api/mcp/ws/{session_id}` | Vulnerable WebSocket endpoint |
| Endpoint | `/api/mcp/*` | Auth-skipped path prefix (pre-fix) |
| Port | 8081 | Default AutoGen Studio port |
| Port | 8080 | Alternate AutoGen Studio port |

### File System

| Platform | Path | Description |
|----------|------|-------------|
| Cross-platform | `autogenstudio/web/routes/mcp.py` | Vulnerable FastAPI route handler |
| Cross-platform | `pyproject.toml` | Version tracking; fixed at 0.7.2 |

### Behavioral

- AutoGen Studio (Python) process spawning unexpected child processes (cmd.exe, powershell.exe, calc.exe, bash, curl, etc.) via the `stdio_client()` path
- WebSocket upgrade requests to localhost ports 8081/8080 containing `/api/mcp/ws/` with `server_params=` in the query string
- Browser automation processes (Playwright, headless Chrome) launched by Python/Node with AutoGen-related command lines navigating to external attacker-controlled content
- Origin header values of `http://127[.]0[.]0[.]1` or `http://localhost` on WebSocket connections originating from agent-rendered content

---

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1203 | Exploitation for Client Execution | Browsing agent renders attacker page that exploits the MCP WebSocket vulnerability |
| T1059 | Command and Scripting Interpreter | Arbitrary command execution via StdioServerParams (calc.exe, powershell.exe, bash -c, etc.) |
| T1059.001 | PowerShell | PoC demonstrates powershell.exe with encoding as spawnable command |
| T1059.006 | Python | AutoGen Studio itself is Python-based; exploitation occurs through Python process |
| T1204.001 | User Execution: Malicious Link | AI agent navigates to attacker-controlled URL containing exploit JavaScript |
| T1190 | Exploit Public-Facing Application | Authentication bypass via middleware skip list grants unauthenticated access to MCP WebSocket endpoint |

---

## Impact Assessment

- **Severity:** High (RCE on developer workstation)
- **Scope:** Limited to developers running AutoGen Studio from the GitHub main branch with MCP support enabled. PyPI users were never exposed.
- **Attack Prerequisites:** Target must be running vulnerable AutoGen Studio build with a web-browsing agent. Attacker must be able to place content on a page the agent visits.
- **Impact:** Full command execution under the developer's user account. Can install malware, steal credentials, pivot to internal networks, access source code repositories.
- **Stealth:** Moderate -- the exploit leaves process creation artifacts but the initial vector (JavaScript in agent-rendered content) may not be logged.

---

## Detection & Remediation

### Immediate Detection

**Microsoft Defender Advanced Hunting (KQL):**

```kql
// Query 1: Suspicious child processes from AutoGen Studio
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessCommandLine matches regex @"(?i)autogenstudio|autogen[\s\_\-]?studio"
   or InitiatingProcessFolderPath matches regex @"(?i)autogenstudio"
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "wsl.exe",
    "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "curl.exe", "wget.exe", "bitsadmin.exe"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

```kql
// Query 2: WebSocket connections to MCP endpoint with server_params
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemotePort in (8081, 8080)
| where RemoteUrl has "/api/mcp/ws/" and RemoteUrl has "server_params="
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp desc
```

<!-- revision: KQL Query 3 (Browser automation with external navigation in agent context) DROPPED — same over-broad behavioral pattern as dropped Sigma Rule 3; fires on normal MultimodalWebSurfer operation. -->

### Remediation

1. **Update immediately:** Pull the latest AutoGen main branch at or after commit b047730, or wait for the next PyPI release (>= 0.7.2).
2. **Verify PyPI installation:** If installed via `pip install autogenstudio`, confirm version is 0.4.2.2 (not affected). Run: `pip show autogenstudio | grep Version`.
3. **Bind to loopback only:** Ensure AutoGen Studio binds exclusively to 127.0.0.1 with firewall rules blocking non-loopback traffic to ports 8081/8080.
4. **Deploy behind authenticated reverse proxy:** Enforce authentication on ALL paths including `/api/mcp/*` and `/api/ws/*`.
5. **Run in sandboxed environment:** Use Microsoft Dev Box, Windows Sandbox, or containers with restricted process execution capabilities.
6. **Separate agent identity:** Do not run browsing agents under the same identity/session as the AutoGen Studio developer interface.

### Long-Term Hardening

- Implement executable allowlisting for MCP server spawning -- only permit pre-approved binaries.
- Apply Content Security Policy headers to prevent agent-rendered pages from making localhost connections.
- Adopt Microsoft Entra Agent ID for identity governance of AI agents.
- Deploy Azure AI Content Safety Prompt Shields to detect indirect prompt injection (XPIA) that could steer agents to malicious pages.

---

## Detection Rules

Two Sigma rules, two Suricata rules, and one Snort rule are provided, targeting the AutoJack exploit chain at process creation and network layers. No YARA rule is included because the vulnerability is a logic flaw exploited via network interaction, not a file-level artifact. All rules passed compilation and backend conversion.

<!-- Validation audit (revision pass):
  Sigma Rule 1: sigma check exit 0, sigma convert splunk exit 0, sigma convert log_scale exit 0. Confidence downgraded to medium. FP note updated.
  Sigma Rule 2: sigma check exit 0, sigma convert splunk exit 0, sigma convert log_scale exit 0. No changes.
  Sigma Rule 3: DROPPED — fires on normal MultimodalWebSurfer operation. No exploit-specific artifact. Wrong altitude.
  Suricata Rule 1: No changes. suricata -T exit 0.
  Suricata Rule 2: Added nocase; after content:"websocket" per RFC 6455. Rev bumped to 2. suricata -T exit 0.
  Snort: No changes. snort -T exit 0.
  KQL Query 3: DROPPED — same over-broad behavioral pattern as Sigma Rule 3.
  MITRE: Removed T1557 (not AiTM), T1548 (not priv-esc). Added T1190 for auth bypass.
  IOCs: Fixed defanging convention statement to note localhost exception.
  No defanged values in rules (rules use real values per logsource-encoding spec).
-->

### Sigma Rules

**Rule 1: AutoGen Studio MCP WebSocket Suspicious Child Process Spawning**
Detects suspicious child process creation (cmd.exe, powershell.exe, calc.exe, etc.) from processes with AutoGen Studio indicators in the parent command line, targeting the final stage of the AutoJack chain where arbitrary commands are spawned via StdioServerParams. compile: PASS | confidence: medium

```yaml
title: AutoGen Studio MCP WebSocket Suspicious Child Process Spawning
id: 7c4a2e9f-3b8d-4f1a-a5c6-0d2e8f1b7a3c
status: experimental
description: >
  Detects suspicious child process creation from AutoGen Studio processes,
  indicative of the AutoJack exploit chain where a malicious webpage triggers
  arbitrary command execution via the MCP WebSocket endpoint. The vulnerable
  endpoint accepted base64-encoded StdioServerParams and passed them directly
  to process spawning without allowlisting.
references:
  - https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/
author: Actioner CTI
date: 2026-06-19
tags:
  - attack.t1059
  - attack.t1203
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentCommandLine|contains:
      - 'autogenstudio'
      - 'autogen_studio'
      - 'autogen-studio'
  selection_suspicious_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\bash.exe'
      - '\wsl.exe'
      - '\certutil.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\curl.exe'
      - '\wget.exe'
      - '\bitsadmin.exe'
      - '\calc.exe'
  condition: selection_parent and selection_suspicious_child
falsepositives:
  - Legitimate AutoGen MCP servers routinely spawn cmd.exe, bash.exe, node.exe via stdio_client()
  - Developer-configured MCP servers using standard system binaries
level: medium
```

**Rule 2: AutoGen Studio MCP WebSocket Connection with server_params Query String**
Detects proxy-logged HTTP/WebSocket connections to AutoGen Studio default ports with URI containing the MCP WebSocket path and the `server_params` query parameter used by the exploit chain. compile: PASS | confidence: high

```yaml
title: AutoGen Studio MCP WebSocket Connection with server_params Query String
id: 9e1b3d5f-7a2c-4e8f-b6d0-1c3a5e7f9b2d
status: experimental
description: >
  Detects network connections to AutoGen Studio's default ports (8081, 8080)
  with URI patterns containing the MCP WebSocket endpoint and server_params
  query parameter. This pattern matches the AutoJack exploit chain where
  attacker-controlled JavaScript opens a WebSocket to localhost with
  base64-encoded command execution parameters.
references:
  - https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/
author: Actioner CTI
date: 2026-06-19
tags:
  - attack.t1059
  - attack.t1203
logsource:
  category: proxy
detection:
  selection_port:
    dst_port:
      - 8081
      - 8080
  selection_uri:
    cs-uri-stem|contains: '/api/mcp/ws/'
  selection_params:
    cs-uri-query|contains: 'server_params='
  condition: selection_port and selection_uri and selection_params
falsepositives:
  - Legitimate MCP server connections using the pre-fix AutoGen Studio API
level: high
```

<!-- revision: Sigma Rule 3 (Browser Automation Process in AI Agent Context, id: 4f8a1c3e-6d2b-5e7a-9b0c-2d4f6a8e0c1b) DROPPED — fires on normal AutoGen MultimodalWebSurfer operation with no exploit-specific artifact. Too behavioral, wrong altitude. -->

### Suricata Rules

**Rule 1: AutoJack MCP WebSocket Command Injection via server_params**
Detects HTTP requests to the AutoGen Studio MCP WebSocket endpoint containing the `server_params` query parameter, which carries base64-encoded command execution payloads. compile: PASS | confidence: high

**Rule 2: AutoGen Studio WebSocket Upgrade to MCP Endpoint**
Detects WebSocket upgrade requests targeting the MCP endpoint, a broader variant that catches upgrade attempts regardless of query string content. compile: PASS | confidence: medium

```
# Rule 1: AutoJack MCP WebSocket Exploit via server_params
alert http any any -> any any (msg:"ETPRO EXPLOIT AutoJack AutoGen Studio MCP WebSocket Command Injection via server_params"; flow:established,to_server; http.uri; content:"/api/mcp/ws/"; fast_pattern; content:"server_params="; http.method; content:"GET"; reference:url,www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/; classtype:web-application-attack; sid:2100100; rev:1;)

# Rule 2: AutoJack WebSocket Upgrade to MCP Endpoint on Localhost Ports
alert http any any -> any any (msg:"ETPRO EXPLOIT AutoGen Studio WebSocket Upgrade Request to MCP Endpoint"; flow:established,to_server; http.uri; content:"/api/mcp/ws/"; fast_pattern; http.header; content:"Upgrade"; content:"websocket"; nocase; reference:url,www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/; classtype:web-application-attack; sid:2100101; rev:2;)
```

### Snort Rules

**Rule 1: AutoJack MCP WebSocket Command Injection via server_params**
Snort 2 equivalent of Suricata Rule 1. Detects HTTP GET requests to the MCP WebSocket endpoint with the server_params query string. compile: PASS | confidence: high

```
alert tcp any any -> any any (msg:"ETPRO EXPLOIT AutoJack AutoGen Studio MCP WebSocket Command Injection via server_params"; flow:established,to_server; content:"/api/mcp/ws/"; http_uri; content:"server_params="; http_uri; content:"GET"; http_method; reference:url,www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/; classtype:web-application-attack; sid:2100100; rev:1;)
```

---

## Lessons Learned

AutoJack demonstrates a systemic risk in the emerging AI agent landscape: **localhost trust boundaries are invalidated when AI agents with browsing capabilities render untrusted content**. The traditional assumption that localhost-bound services are isolated from external threats breaks down when a browsing agent acts as a bridge between attacker-controlled web content and local service endpoints. This is not unique to AutoGen -- any AI agent framework that (a) renders arbitrary web content locally and (b) exposes authenticated or unauthenticated localhost services is potentially vulnerable to the same class of attack.

Key takeaways for AI agent developers:
1. Never exempt API paths from authentication based on the assumption that WebSocket handlers will implement their own checks.
2. Never accept executable parameters from client-supplied input without strict allowlisting.
3. Treat AI browsing agents as untrusted clients relative to other localhost services.
4. The disclosure model here was responsible -- Microsoft identified, fixed, and disclosed the vulnerability before it reached any published release, limiting real-world impact.

---

## Sources

- [AutoJack: How a Single Page Can RCE the Host Running Your AI Agent (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/) -- Primary technical disclosure by Microsoft Defender Security Research Team
- [Microsoft Says Web-Enabled AI Agents Can Trigger Host-Level RCE (CSO Online)](https://www.csoonline.com/article/4187155/microsoft-says-web-enabled-ai-agents-can-trigger-host-level-rce.html) -- Coverage with additional context on the vulnerability class
- [AutoJack: How A Single Page Can RCE The Host Running Your AI Agent (Arrowwood Services)](https://www.arrowwoodservices.com/autojack-how-a-single-page-can-rce-the-host-running-your-ai-agent/) -- Syndicated coverage of the Microsoft disclosure
- [Fix: Improve AutoGen Studio - Commit b047730 (GitHub, microsoft/autogen)](https://github.com/microsoft/autogen/commit/b047730) -- Fix commit by Victor Dibia deprecating FunctionTool and hardening MCP WebSocket endpoint
- [MCP Tool Poisoning Can Enable Arbitrary Code Execution -- Issue #7427 (GitHub, microsoft/autogen)](https://github.com/microsoft/autogen/issues/7427) -- Related MCP attack surface discussion in AutoGen repository
- [AutoGen Security Policy (GitHub, microsoft/autogen)](https://github.com/microsoft/autogen/security/policy) -- Microsoft AutoGen security reporting and policy

---
*Report generated by Actioner*
