# Technical Analysis Report: F5 NGINX Critical Vulnerabilities (2026-06-18)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-18
Version: 1.0

## Executive Summary

On June 17-18, 2026, F5 released out-of-band security updates for multiple vulnerabilities affecting NGINX Open Source, NGINX Plus, and NGINX Gateway Fabric. Two of the flaws -- CVE-2026-42530 (use-after-free in HTTP/3 QUIC session handling) and CVE-2026-42055 (heap buffer overflow in HTTP/2 and gRPC proxy modules) -- carry critical CVSS 4.0 scores of 9.2 and can be exploited by remote, unauthenticated attackers to crash worker processes and potentially achieve arbitrary code execution if ASLR is disabled or bypassed. Two additional high-severity vulnerabilities in NGINX Gateway Fabric (CVE-2026-11311 and CVE-2026-50107) allow authenticated attackers to inject arbitrary NGINX configuration directives via unsanitized CRD fields, potentially exposing pod filesystem data or proxying traffic to attacker-controlled endpoints. F5 reports no exploitation in the wild at the time of disclosure. No public proof-of-concept exploit code is available.

## Background: NGINX

NGINX is the world's most widely deployed web server and reverse proxy, powering an estimated 34% of all websites globally. F5 Networks acquired NGINX in 2019 and maintains both the open-source and commercial NGINX Plus products, along with the Kubernetes-native NGINX Gateway Fabric and NGINX Ingress Controller. Given its ubiquity as an internet-facing service, vulnerabilities in NGINX carry outsized risk -- particularly those reachable without authentication from the network.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-17 | NGINX 1.31.2 (mainline) and 1.30.3 (stable) released with security fixes |
| 2026-06-17 | NGINX Gateway Fabric 2.6.4 released addressing CVE-2026-11311 and CVE-2026-50107 |
| 2026-06-17 | F5 publishes security advisories K000161616, K000161584, K000161585, K000161785 |
| 2026-06-18 | SecurityWeek publishes article on the vulnerabilities; F5 security notification K000161614 issued |

## Root Cause: Memory Safety and Input Validation Flaws

The critical NGINX Open Source/Plus vulnerabilities stem from memory safety issues in C code:

- **CVE-2026-42530**: A use-after-free condition in the HTTP/3 QUIC session processing path, where a specially crafted QUIC session triggers access to freed memory in the worker process.
- **CVE-2026-42055**: A heap-based buffer overflow in the `ngx_http_proxy_v2_module` and `ngx_http_grpc_module` triggered when proxying specially crafted requests to HTTP/2 or gRPC backends under specific configuration conditions (`ignore_invalid_headers off;` combined with large `large_client_header_buffers` values).

The NGINX Gateway Fabric vulnerabilities stem from insufficient input validation:

- **CVE-2026-50107** (CWE-74): User-supplied strings from the NginxProxy CRD access log format setting are rendered directly into NGINX configuration templates without sanitization.
- **CVE-2026-11311**: Insufficient validation of OIDC extra args in AuthenticationFilter and Server Tokens in NginxProxy CRDs.

## Technical Analysis of the Malicious Payload

### 1. CVE-2026-42530 -- HTTP/3 Use-After-Free (Critical, CVSS 9.2)

A use-after-free vulnerability in the HTTP/3 subsystem is triggered when processing a specially crafted QUIC session. The flaw causes worker process memory corruption or segmentation fault. Under conditions where ASLR is disabled or bypassed, this could potentially be leveraged for arbitrary code execution. The vulnerability affects NGINX mainline versions 1.31.0 through 1.31.1 (HTTP/3 support was introduced in 1.25.0 but this specific flaw is limited to the 1.31.x branch). The vulnerability was discovered and reported by Trung Nguyen of CyStack.

**Exploitation prerequisites:**
- NGINX must have HTTP/3 (QUIC) enabled in its configuration
- Attacker must be able to send crafted QUIC packets to the NGINX server
- No authentication required

### 2. CVE-2026-42055 -- Heap Buffer Overflow in HTTP/2/gRPC Proxy (Critical, CVSS 9.2)

A heap memory buffer overflow can occur in the worker process when all of the following configuration conditions are met:
1. `ignore_invalid_headers off;` is set
2. `large_client_header_buffers` is configured with large values
3. The server proxies requests to HTTP/2 or gRPC backends

A specially crafted request to such a server can trigger heap buffer overflow, causing worker process memory corruption or segmentation fault. This vulnerability affects a much wider version range: NGINX 1.13.10 through 1.31.1. The vulnerability was discovered and reported by Mufeed VH of Winfunc Research.

**Exploitation prerequisites:**
- Specific NGINX configuration with `ignore_invalid_headers off;` and large header buffers
- HTTP/2 or gRPC backend proxying must be configured
- No authentication required

### 3. CVE-2026-50107 -- Gateway Fabric Access Log Format Injection (High, CVSS 8.1/8.6)

An injection vulnerability in the NGINX configuration generator component of NGINX Gateway Fabric. User-supplied string values from the NginxProxy Custom Resource Definition (CRD) access log format setting are rendered directly into NGINX configuration templates without sanitization or escaping. An authenticated attacker with permission to create or modify NginxProxy CRDs can inject arbitrary NGINX configuration directives.

**Exploitation prerequisites:**
- Authenticated access to Kubernetes API with permissions to modify NginxProxy CRDs
- NGINX Gateway Fabric versions 2.3.0 through 2.6.3

### 4. CVE-2026-11311 -- Gateway Fabric OIDC/Server Token Injection (High)

Insufficient validation of OIDC extra args in AuthenticationFilter and Server Tokens in NginxProxy CRDs allows similar configuration injection attacks. This was fixed alongside CVE-2026-50107 in the same pull request (PR-5467).

### 5. Additional Medium/Low Severity Fixes in 1.31.2

- **CVE-2026-48142** (Low): Heap memory buffer overread in the `ngx_http_charset_module` during UTF-8 charset decoding via the `charset_map` directive, potentially causing limited worker process memory disclosure. Discovered by Han Yan of Xiaomi and p4p3r of CYBERONE.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through.

### Package / Software Level

| Package / Component | Vulnerable Versions | Fixed Version | Description |
|---------------------|---------------------|---------------|-------------|
| NGINX Open Source (mainline) | 1.31.0 - 1.31.1 | 1.31.2 | CVE-2026-42530 (HTTP/3 UAF) |
| NGINX Open Source (mainline) | 1.13.10 - 1.31.1 | 1.31.2 | CVE-2026-42055 (heap overflow) |
| NGINX Open Source (stable) | affected versions | 1.30.3 | CVE-2026-42055 (heap overflow) |
| NGINX Plus | R32 - R36 | R36 P4 / R32 P6 | Both critical CVEs |
| NGINX Gateway Fabric | 2.3.0 - 2.6.3 | 2.6.4 | CVE-2026-11311, CVE-2026-50107 |
| NGINX Instance Manager | 2.16.0 - 2.22.0 | Consult F5 advisory | Downstream impact |
| NGINX App Protect WAF | 4.9.0 - 4.16.0, 5.1.0 - 5.8.0 | Consult F5 advisory | Downstream impact |
| NGINX Ingress Controller | 3.5.0 - 3.7.2, 4.0.0 - 4.0.1, 5.0.0 - 5.4.2 | Consult F5 advisory | Downstream impact |

### File System

No file-system IOCs are applicable. These are memory corruption and configuration injection vulnerabilities with no dropped payloads.

### Network

No network-level IOCs are available. The exploitation payloads are protocol-level (crafted QUIC sessions, crafted HTTP requests) without distinctive byte signatures documented in public advisories.

### Behavioral

- **Worker process crashes**: Repeated NGINX worker process restarts or segmentation faults in logs may indicate exploitation attempts against CVE-2026-42530 or CVE-2026-42055
- **Unexpected NGINX configuration changes**: In Kubernetes environments running NGINX Gateway Fabric, unauthorized modifications to NginxProxy CRDs may indicate exploitation of CVE-2026-50107 or CVE-2026-11311
- **NGINX error log entries**: `signal 11 (SIGSEGV)` or `worker process exited on signal 11` entries correlating with HTTP/3 or proxied HTTP/2/gRPC traffic

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1190 | Exploit Public-Facing Application | Remote exploitation of NGINX via crafted QUIC sessions (CVE-2026-42530) or HTTP requests (CVE-2026-42055) |
| T1499.004 | Application or System Exploitation (Endpoint DoS) | Worker process crash/restart causing denial of service |
| T1203 | Exploitation for Client Execution | Potential arbitrary code execution if ASLR bypassed |
| T1562.001 | Disable or Modify Tools | Gateway Fabric config injection could disable security controls (CVE-2026-50107, CVE-2026-11311) |
| T1557 | Adversary-in-the-Middle | Gateway Fabric injection could proxy traffic to attacker-controlled endpoints |

## Impact Assessment

**Breadth:** NGINX is deployed on an estimated 400+ million websites globally. The HTTP/3 use-after-free (CVE-2026-42530) has a narrow attack surface limited to the 1.31.0-1.31.1 mainline versions with HTTP/3 enabled. The heap overflow (CVE-2026-42055), however, affects versions dating back to 1.13.10 (released circa 2017), though it requires a non-default configuration (`ignore_invalid_headers off;`). The Gateway Fabric vulnerabilities affect Kubernetes deployments specifically.

**Severity:** Critical -- both memory corruption vulnerabilities can cause denial of service (worker process restart) without authentication, and may enable arbitrary code execution under specific conditions (ASLR disabled/bypassed).

**Stealth:** Exploitation would manifest as worker process crashes visible in NGINX error logs. However, successful code execution without crashing (a more sophisticated attack) could be stealthy.

**Current exploitation status:** F5 reports no exploitation in the wild as of the disclosure date. No public PoC exists.

## Detection & Remediation

### Immediate Detection

Check NGINX version on running instances:

```bash
# Check NGINX version
nginx -v 2>&1

# Check for HTTP/3 configuration (CVE-2026-42530 prerequisite)
grep -r "listen.*quic\|http3" /etc/nginx/ 2>/dev/null

# Check for vulnerable proxy configuration (CVE-2026-42055 prerequisite)
grep -r "ignore_invalid_headers\s*off" /etc/nginx/ 2>/dev/null
grep -r "large_client_header_buffers" /etc/nginx/ 2>/dev/null

# Check for worker process crashes in error log
grep -i "signal 11\|SIGSEGV\|worker process exited" /var/log/nginx/error.log

# Check NGINX Gateway Fabric version (Kubernetes)
kubectl get deployment -n nginx-gateway -o jsonpath='{.items[*].spec.template.spec.containers[*].image}'
```

### Remediation

1. **Immediate -- Update NGINX:**
   - NGINX Open Source mainline: upgrade to 1.31.2+
   - NGINX Open Source stable: upgrade to 1.30.3+
   - NGINX Plus: apply R36 P4 or R32 P6 patches

2. **Immediate -- Update NGINX Gateway Fabric:**
   - Upgrade to version 2.6.4+

3. **Workaround for CVE-2026-42055** (if patching is delayed):
   - Ensure `ignore_invalid_headers` is set to `on` (the default) or remove any `ignore_invalid_headers off;` directives
   - Review and reduce `large_client_header_buffers` values

4. **Workaround for CVE-2026-42530** (if patching is delayed):
   - Disable HTTP/3 (QUIC) support if not required by removing `quic` from `listen` directives

5. **RBAC hardening for Gateway Fabric:**
   - Audit and restrict Kubernetes RBAC permissions for creating/modifying NginxProxy and AuthenticationFilter CRDs

### Long-Term Hardening

- Implement a vulnerability management process that tracks NGINX versions across all deployments
- Enable ASLR on all systems running NGINX (should be default on modern Linux) to raise the bar for code execution
- Monitor NGINX error logs for abnormal worker process terminations as an early warning indicator
- For Kubernetes deployments, enforce admission control policies that validate CRD modifications
- Consider deploying a WAF in front of NGINX to filter malformed requests at the protocol level

## Detection Rules

These vulnerabilities are memory corruption flaws (use-after-free, heap buffer overflow) and control-plane configuration injection issues. The exploitation payloads are protocol-level constructs (malformed QUIC sessions, crafted HTTP proxy requests, Kubernetes CRD modifications) with no distinctive, static network signatures documented in public advisories or PoC code. No public proof-of-concept exploits are available to derive byte-level patterns from.

**No production-ready detection rules are viable for these vulnerabilities.** The appropriate defensive response is:

1. **Version detection**: Identify and patch all vulnerable NGINX instances using asset inventory and vulnerability scanning tools
2. **Configuration auditing**: Check for the prerequisite configurations that enable exploitation (HTTP/3 enabled, `ignore_invalid_headers off;`)
3. **Crash monitoring**: Alert on NGINX worker process segmentation faults (`signal 11`) as a behavioral indicator of potential exploitation attempts
4. **Kubernetes audit logging**: Monitor for unauthorized modifications to NginxProxy and AuthenticationFilter CRDs in clusters running NGINX Gateway Fabric

## Lessons Learned

1. **Memory safety in C remains a persistent risk.** NGINX, written in C, continues to produce memory corruption vulnerabilities. The CVE-2026-42055 heap overflow existed across versions spanning back to 2017, illustrating how long such bugs can persist undetected in mature codebases.

2. **Configuration-dependent attack surfaces create blind spots.** CVE-2026-42055 requires non-default configuration settings to be exploitable, which means traditional vulnerability scanning that only checks versions may overcount exposure while configuration auditing is neglected.

3. **Kubernetes control plane security is critical.** The Gateway Fabric injection flaws (CVE-2026-50107, CVE-2026-11311) demonstrate that insufficient input validation in CRD processing can turn a control-plane misconfiguration into a data-plane compromise. Organizations running NGINX Gateway Fabric should enforce strict RBAC and admission control policies.

4. **HTTP/3 and QUIC expand the attack surface.** As organizations adopt HTTP/3, they inherit new parsing complexity in the QUIC protocol stack. CVE-2026-42530 is a reminder that newer protocol support introduces fresh attack surface that may not be as battle-tested as the HTTP/1.1 and HTTP/2 code paths.

## Sources

- [SecurityWeek - F5 Patches Critical, High-Severity NGINX Vulnerabilities](https://www.securityweek.com/f5-patches-critical-high-severity-nginx-vulnerabilities/) -- primary reporting on the vulnerability disclosure
- [NGINX Security Advisories](https://nginx.org/en/security_advisories.html) -- official NGINX security advisory page listing all CVEs and affected versions
- [NGINX 1.31.2 Changelog](https://nginx.org/en/CHANGES) -- detailed changelog with security fix descriptions and credits
- [F5 Advisory K000161616 - CVE-2026-42530](https://my.f5.com/manage/s/article/K000161616) -- F5 advisory for the HTTP/3 use-after-free vulnerability
- [F5 Advisory K000161584 - CVE-2026-42055](https://my.f5.com/manage/s/article/K000161584) -- F5 advisory for the heap buffer overflow vulnerability
- [F5 Advisory K000161585 - CVE-2026-48142](https://my.f5.com/manage/s/article/K000161585) -- F5 advisory for the charset module buffer overread
- [F5 Advisory K000161785 - CVE-2026-50107](https://my.f5.com/manage/s/article/K000161785) -- F5 advisory for the Gateway Fabric access log injection
- [F5 Security Notification K000161614](https://my.f5.com/manage/s/article/K000161614) -- consolidated F5 security notification
- [NGINX Gateway Fabric Changelog](https://github.com/nginx/nginx-gateway-fabric/blob/main/CHANGELOG.md) -- changelog documenting CVE-2026-11311 and CVE-2026-50107 fixes in v2.6.4
- [CVE-2026-50107 - THREATINT](https://cve.threatint.eu/CVE/CVE-2026-50107) -- CVE record with CVSS scores and CWE classification
- [CCB Belgium Advisory](https://ccb.belgium.be/advisories/warning-multiple-vulnerabilities-nginx-leading-remote-code-execution-and-allowing-rate) -- Belgian Cyber Security Centre advisory on NGINX vulnerabilities
- [LinuxCompatible - NGINX 1.31.2 Update](https://www.linuxcompatible.org/story/nginx-1312-update-fixes-critical-memory-flaws-and-improves-proxy-reliability) -- coverage of the 1.31.2 release

---
*Report generated by Actioner*
