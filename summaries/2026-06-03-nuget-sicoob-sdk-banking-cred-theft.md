# Technical Analysis Report: Malicious `Sicoob.Sdk` NuGet Package — Brazilian Banking Credential & PFX Certificate Theft (2026-06-03)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-06-03
Version: 1.1 (FINAL)

## Executive Summary

A malicious NuGet package named `Sicoob.Sdk` impersonated the official software development kit of Sicoob, one of Brazil's largest financial cooperatives. Discovered by Socket Security (researcher Kirill Boychenko), the package weaponized the `SicoobClient` class so that, at object-construction time, it read the developer-supplied PFX client certificate from disk, base64-encoded it, and exfiltrated it together with the plaintext PFX password and the client ID to a hardcoded attacker-controlled Sentry endpoint. The malicious branch fired only when the `isSandbox` constructor flag was `false` — i.e., when targeting production banking integrations — and additionally siphoned raw boleto (Brazilian payment-slip) API responses, exposing transaction amounts, due dates, and payer/payee data.

The package was published May 5, 2026 and reached version 2.0.4 by May 6, 2026, accumulating 484 downloads across six versions before NuGet blocked the `sicoob` owner account following responsible disclosure. The attacker reinforced the deception with a fresh, unverified GitHub organization (`Sicoob-Cooperativa`) hosting clean source that did not contain the credential-stealing logic present in the distributed DLL, and the rogue account published 11 additional Sicoob-branded packages. This is a textbook software supply-chain / masquerading attack against financial-services developers; the unique hardcoded Sentry tenant subdomain provides a high-fidelity detection anchor.

## Background: Sicoob and the .NET / NuGet Ecosystem

Sicoob (Sistema de Cooperativas de Crédito do Brasil) is a major Brazilian credit-cooperative system whose APIs (Pix, boletos/cobrança, conta corrente, Open Finance) are consumed by .NET developers via mutual-TLS (mTLS) authentication using PFX client certificates. A legitimate-looking `Sicoob.Sdk` NuGet package is therefore highly attractive bait: developers integrating it must supply exactly the secrets an attacker wants — a client ID, the path to a PFX file, and the PFX password — making constructor-time theft devastatingly effective.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-04 | Attacker creates GitHub org `Sicoob-Cooperativa`; contributor `joaobcdev` created ~2 minutes later |
| 2026-05-05 | `Sicoob.Sdk` first published to NuGet by owner account `sicoob` |
| 2026-05-06 | Package iterated to version 2.0.4 |
| 2026-05 | Socket Security identifies the package; responsible disclosure to NuGet |
| 2026-05 | NuGet blocks the `sicoob` owner account; package removed |

## Root Cause: Trojanized Library in the Supply Chain (Source/Binary Mismatch)

The attacker published a clean public `SicoobClient.cs` on GitHub (legitimate mTLS certificate loading only) while shipping a compiled `Sicoob.Sdk.dll` on NuGet that contained additional credential-capture logic absent from the source. Developers (and Google's AI search surfacing) were misled into treating the package as the official SDK. Because the malicious code executed in the constructor rather than in an explicit API call, it ran before any safety review of method usage could intervene.

## Technical Analysis of the Malicious Payload

### 1. Trigger — Constructor-time Execution

The malicious branch lives in the `SicoobClient` constructor and activates when the `isSandbox` parameter is `false` (production usage). Simply instantiating the client with real credentials triggers exfiltration; no further method call is required.

### 2. Credential & Certificate Capture

On the malicious path the DLL:
1. Reads the PFX from disk via `System.IO.File.ReadAllBytes` (PFX path supplied by the developer).
2. Base64-encodes the certificate bytes via `System.Convert.ToBase64String`.
3. Bundles the runtime-supplied **client ID**, the **plaintext PFX password**, and the **base64-encoded PFX** (private key + client certificate).

It also captures **raw boleto API responses** (transaction details, amounts, due dates, identifiers, payer/payee info).

### 3. C2 / Exfiltration Infrastructure

Exfiltration abuses the legitimate Sentry error-reporting SDK as a covert channel. `SentrySdk.Init` is called with a hardcoded attacker DSN and the stolen data is transmitted via `SentrySdk.CaptureMessage`. Because it rides Sentry's normal HTTPS ingest, the traffic blends with benign telemetry — the distinguishing feature is the attacker's **unique Sentry tenant subdomain / project ID** (see IOCs). The DLL ships at `lib/net8.0/Sicoob.Sdk.dll`.

### 4. Platform-Specific Behavior

Cross-platform .NET 8 library; the malicious behavior is OS-agnostic (any host building/running a .NET app that references the package). On Windows, the DLL load is observable via image-load telemetry; the exfil DNS/TLS is observable on any platform.

### 5. Anti-Forensics / Evasion Techniques

Source/binary mismatch (clean GitHub source vs. trojanized published DLL); use of a *legitimate* observability SDK (Sentry) and HTTPS to blend exfil with normal app telemetry; `isSandbox=false` gating so the payload stays dormant during sandbox/CI testing and only fires against production credentials.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** URLs use `hxxps://`; dots in hosts use `[.]`.

### Package / Software Level

| Package / Component | Malicious Version | Description |
|---------------------|-------------------|-------------|
| `Sicoob.Sdk` (NuGet, owner `sicoob`) | 2.0.0 – 2.0.4 | Trojanized SDK; constructor-time PFX/credential exfil |
| `lib/net8.0/Sicoob.Sdk.dll` | — | Malicious compiled assembly inside the package |
| `Sicoob-Cooperativa.Sicoob.Auth` and 10 sibling packages | — | Same publisher, untrusted by association (CobrancaV3, ContaCorrente, ConvenioPagamentos, Investimentos, OpenFinance, PagamentosPix, PagamentosV3, Pix, Poupanca, SpbTransferencias) |

### File System

| Platform | Path | Hash (SHA256) | Description |
|----------|------|---------------|-------------|
| Any (.NET 8) | `…/Sicoob.Sdk.dll` (package layout `lib/net8.0/`) | not published | Trojanized assembly |

### Network

| Type | Value | Context |
|------|-------|---------|
| Sentry DSN | `hxxps://d565e3f03d0b1a7c8935d7ff94237316[at]o4511335034847232[.]ingest[.]de[.]sentry[.]io/4511337546317904` | Hardcoded exfil endpoint |
| Host (SNI / DNS) | `o4511335034847232[.]ingest[.]de[.]sentry[.]io` | Attacker Sentry ingest tenant |
| Sentry project ID | `4511337546317904` | Exfil project |
| Sentry public key | `d565e3f03d0b1a7c8935d7ff94237316` | DSN auth key embedded in DLL |

### Accounts / Infrastructure

| Type | Value | Context |
|------|-------|---------|
| GitHub org | `github[.]com/Sicoob-Cooperativa` (created 2026-05-04, unverified) | Decoy clean source |
| GitHub user | `joaobcdev` | Contributor created ~2 min after the org |
| NuGet owner | `sicoob` | Publisher of the malicious package |

### Behavioral

A .NET build/run process (`dotnet`, `MSBuild`, an app host, or a NuGet restore task) that loads `Sicoob.Sdk.dll` and then makes an outbound TLS/DNS connection to `o4511335034847232.ingest.de.sentry.io` — especially where the org does not otherwise use that Sentry tenant — is a strong indicator of credential exfiltration.

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious package masquerading as the official Sicoob SDK |
| T1204.005 | User Execution: Malicious Library | Developer references/instantiates the trojanized library |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Package name, GitHub org, and source mimic the real SDK |
| T1552.001 | Unsecured Credentials: Credentials in Files | Reads PFX certificate file from disk |
| T1552.004 | Unsecured Credentials: Private Keys | Steals PFX private key + password |
| T1005 | Data from Local System | Captures boleto API responses |
| T1041 | Exfiltration Over C2 Channel | Sends data via Sentry `CaptureMessage` |
| T1567 | Exfiltration Over Web Service | Abuses legitimate Sentry SaaS as exfil channel |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS to Sentry ingest |

## Impact Assessment

Breadth: 484 downloads of the malicious package (≈6,000 combined across the publisher's packages); blocked after disclosure. Depth: catastrophic per-victim — full mTLS client certificate + private key + password + client ID grants an attacker the ability to authenticate to Sicoob banking APIs as the victim and to read/initiate financial transactions (Pix, boletos). Stealth: high — constructor-time trigger, `isSandbox` gating, and exfil disguised as legitimate Sentry telemetry over HTTPS.

## Detection & Remediation

### Immediate Detection

- Inventory NuGet usage for `Sicoob.Sdk` (any 2.0.0–2.0.4) and any `Sicoob-Cooperativa.*` package: `dotnet list package` / search `packages.lock.json`, `*.csproj`, and the NuGet global cache (`~/.nuget/packages/sicoob.sdk`).
- Search egress logs / Sentry-less environments for DNS or TLS SNI to `o4511335034847232.ingest.de.sentry.io`.
- Hunt for the DSN public key `d565e3f03d0b1a7c8935d7ff94237316` in build artifacts and binaries.

### Remediation

1. Remove the package and purge it from the NuGet cache and build outputs; rebuild from the legitimate first-party SDK.
2. **Treat any PFX certificate, password, or client ID ever used with this package as compromised — revoke and reissue the Sicoob mTLS client certificates and rotate credentials immediately.**
3. Review Sicoob API logs for unauthorized authentications/transactions during the exposure window.

### Long-Term Hardening

Pin packages by version + hash (lockfiles), require provenance/signed packages, restrict outbound egress from build agents, and treat constructor-time side effects in dependencies as a code-review red flag. Verify publisher identity rather than trusting name resemblance or AI-surfaced recommendations.

## Detection Rules

These detections target the malicious `Sicoob.Sdk` package end-to-end: the trojanized DLL load (Sigma), and the exfiltration to the attacker's unique Sentry tenant (Sigma DNS, Snort/Suricata TLS+DNS), plus a file-level YARA signature on the embedded DSN and credential-capture API chain. PoC/advisory-specific altitude, strict. Note: compiles/validates is not the same as fires — verify field mappings (Sysmon vs. EDR) and that your environment actually logs DNS/image-load before relying on these.

### Sigma: Sicoob.Sdk Exfiltration via Attacker Sentry Ingest Host (DNS)
Detects DNS resolution of the attacker's unique Sentry ingest subdomain used to exfiltrate stolen PFX/credentials.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: sigma check 0; splunk 0; log_scale 0. Anchor = full attacker Sentry tenant FQDN (org id 4511335034847232 + project 4511337546317904), not a generic sentry.io match, so benign-overlap is near zero. dns_query category is product-agnostic (fires on Sysmon EID22, Zeek, EDR DNS). -->
```yaml
title: Sicoob.Sdk NuGet Credential Exfiltration via Sentry Ingest Host
id: a20a7faa-3385-4b4b-ad98-5051c0e00669
status: experimental
description: >
    Detects DNS resolution of the attacker-controlled Sentry ingest host used by the
    malicious Sicoob.Sdk NuGet package to exfiltrate PFX certificates, PFX passwords,
    client IDs, and boleto API responses. The subdomain encodes the attacker's unique
    Sentry organization/project ID and is not a benign Sentry tenant for normal apps.
references:
    - https://socket.dev/blog/malicious-nuget-package-impersonates-sicoob-sdk
    - https://thehackernews.com/2026/05/malicious-sicoob-nuget-steals-banking.html
author: Actioner
date: 2026-06-03
tags:
    - attack.t1041
    - attack.t1567
    - attack.t1552.004
logsource:
    category: dns_query
detection:
    selection:
        QueryName: 'o4511335034847232.ingest.de.sentry.io'
    condition: selection
falsepositives:
    - None expected; this Sentry tenant subdomain is attacker-controlled
level: critical
```

### Sigma: Sicoob.Sdk Malicious DLL Load
Detects loading of the trojanized `Sicoob.Sdk.dll` shipped by the malicious package. Name-only match — pair with the DNS rule; a benign rebuild of the attacker's decoy clean-source repo compiles to the same DLL name.
**Status:** compile ✅ compiles · confidence: medium
<!-- revision: critic FIX — downgraded high→medium and level high→medium. Anchor is name-only `endswith '\Sicoob.Sdk.dll'` with no hash; the attacker's decoy clean-source GitHub repo can be rebuilt to an identically-named benign DLL, so a name match alone does not confirm the trojanized binary. -->
<!-- audit: sigma check 0; splunk 0; log_scale 0. image_load category (Sysmon EID7). No published SHA256 to anchor on, so this keys on the module name only. endswith anchors on the published package layout lib/net8.0/Sicoob.Sdk.dll. -->
```yaml
title: Sicoob.Sdk Malicious DLL Load or Install in .NET Build Context
id: 8da17c5f-2004-433b-b40a-a87c3e4fde42
status: experimental
description: >
    Detects loading of the trojanized Sicoob.Sdk.dll shipped by the malicious Sicoob.Sdk
    NuGet package (versions 2.0.0-2.0.4) whose SicoobClient constructor reads and base64-encodes
    PFX certificates and exfiltrates them. Matches the module path published in the package layout.
references:
    - https://socket.dev/blog/malicious-nuget-package-impersonates-sicoob-sdk
    - https://thehackernews.com/2026/05/malicious-sicoob-nuget-steals-banking.html
author: Actioner
date: 2026-06-03
tags:
    - attack.t1195.002
    - attack.t1204.005
    - attack.t1552.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\Sicoob.Sdk.dll'
    condition: selection
falsepositives:
    - A benign rebuild of the attacker's decoy clean-source repo produces an identically-named DLL; name-only match, no hash anchor
level: medium
```

### Snort: Sicoob.Sdk Exfil to Attacker Sentry Ingest Host (TLS SNI + DNS)
Detects the TLS ClientHello SNI and the DNS query for the attacker's Sentry ingest host. Snort 2.9.20 has no `tls.sni` buffer, so the SNI rule content-matches the cleartext host in the ClientHello on tcp/443.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: snort -c /tmp/snort-run.conf -T exit 0 (2.9.20). 2.x dialect: protocol tcp/udp (not http/tls), no sticky-buffer dot syntax. SNI travels cleartext in ClientHello -> tcp 443 content match. DNS rule uses label-length encoding |11|o4511335034847232|06|ingest|02|de|06|sentry|02|io|00| (17-char label = 0x11). sid 2100001-2100002. fast_pattern on the unique 37-char host. -->
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Actioner - Sicoob.Sdk NuGet Exfil TLS ClientHello SNI to Attacker Sentry Ingest Host"; flow:established,to_server; content:"o4511335034847232.ingest.de.sentry.io"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-package-impersonates-sicoob-sdk; sid:2100001; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"Actioner - Sicoob.Sdk NuGet Exfil DNS Query for Attacker Sentry Ingest Host"; content:"|11|o4511335034847232|06|ingest|02|de|06|sentry|02|io|00|"; nocase; fast_pattern; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-package-impersonates-sicoob-sdk; sid:2100002; rev:1;)
```

### Suricata: Sicoob.Sdk Exfil to Attacker Sentry Ingest Host (TLS SNI + DNS)
Detects the exfil connection via the `tls.sni` and `dns.query` sticky buffers matching the attacker's unique Sentry ingest host.
**Status:** compile ✅ compiles · confidence: high
<!-- audit: suricata -T -S ... -l /tmp exit 0 (7.0.3). dotted sticky buffers tls.sni / dns.query; bsize:37 anchors the exact host length to avoid substring drift; msg prefixed "Actioner - "; sid 2200001-2200002. -->
```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Actioner - Sicoob.Sdk NuGet Exfil TLS SNI to Attacker Sentry Ingest Host"; flow:established,to_server; tls.sni; content:"o4511335034847232.ingest.de.sentry.io"; nocase; bsize:37; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-package-impersonates-sicoob-sdk; metadata:author Actioner, created_at 2026-06-03; sid:2200001; rev:1;)
alert dns $HOME_NET any -> any any (msg:"Actioner - Sicoob.Sdk NuGet Exfil DNS Query for Attacker Sentry Ingest Host"; dns.query; content:"o4511335034847232.ingest.de.sentry.io"; nocase; bsize:37; classtype:trojan-activity; reference:url,socket.dev/blog/malicious-nuget-package-impersonates-sicoob-sdk; metadata:author Actioner, created_at 2026-06-03; sid:2200002; rev:1;)
```

### YARA: Sicoob.Sdk Trojanized Assembly
Detects the malicious `Sicoob.Sdk.dll` via the embedded attacker Sentry DSN/host/project ID plus the `SicoobClient` class and the PFX-capture / Sentry API chain.
**Status:** compile ✅ compiles · confidence: high
<!-- revision: critic FIX — removed `sample: fired ✓` tag. No real source-published sample/SHA256 exists; the only "positive" was a string bundle assembled from the very IOCs this rule keys on (fabricated to match the rule), which critic gate #5 forbids — that proves nothing about real-data efficacy. Corroboration is the published DSN/ingest host/SicoobClient class strings from the Socket analysis, not a confirmed binary. Confidence kept high on artifact strength (unique DSN+host+project anchor AND class AND ≥2 capture APIs). -->
<!-- audit: yarac exit 0. Compile-only; not sample-tested against a real binary (none published). ascii+wide covers UTF-8/UTF-16 string storage in the assembly. Condition requires unique DSN/host/project anchor AND class AND 2 capture APIs. No SHA256 published; provenance is the Socket-published DSN/host/class strings. -->
```yara
rule Malware_Sicoob_Sdk_NuGet_CredTheft
{
    meta:
        description = "Detects the malicious Sicoob.Sdk NuGet DLL that exfiltrates PFX certificates and banking credentials to a hardcoded Sentry DSN"
        author = "Actioner"
        date = "2026-06-03"
        reference = "https://socket.dev/blog/malicious-nuget-package-impersonates-sicoob-sdk"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $dsn      = "d565e3f03d0b1a7c8935d7ff94237316" ascii wide
        $host     = "o4511335034847232.ingest.de.sentry.io" ascii wide
        $proj     = "4511337546317904" ascii wide
        $cls      = "SicoobClient" ascii wide
        $api1     = "ReadAllBytes" ascii wide
        $api2     = "ToBase64String" ascii wide
        $sentry1  = "SentrySdk" ascii wide
        $sentry2  = "CaptureMessage" ascii wide

    condition:
        ($dsn or $host or $proj) and
        $cls and
        2 of ($api1, $api2, $sentry1, $sentry2)
}
```

## Lessons Learned

Constructor-time side effects in third-party libraries are an underappreciated supply-chain risk: they execute the moment an object is created, before any explicit API surface is reviewed. Source-on-GitHub does not equal binary-on-registry — defenders must verify the *published artifact*, not the advertised source. Attackers increasingly abuse legitimate SaaS (here, Sentry) as exfil channels to evade naive network egress controls; the durable defense is identity/provenance verification of dependencies plus least-privilege egress from build and CI hosts. Finally, AI-surfaced package recommendations can launder malicious packages into a trusted-looking result — treat them as untrusted.

## Sources

- [Socket — Malicious NuGet Package Impersonates Sicoob SDK](https://socket.dev/blog/malicious-nuget-package-impersonates-sicoob-sdk) — primary technical analysis: package id/versions, SicoobClient constructor behavior, hardcoded Sentry DSN, IL-level API chain, GitHub decoy org, sibling packages
- [The Hacker News — Malicious Sicoob NuGet Steals Banking Credentials](https://thehackernews.com/2026/05/malicious-sicoob-nuget-steals-banking.html) — corroborating coverage: package id/versions, download count, publisher, exfil method
- [Security Online — Sicoob SDK Banking Malware NuGet Attack](https://securityonline.info/sicoob-sdk-banking-malware-nuget-attack/) — corroborating coverage: constructor-time trigger, PFX exfil, decoy GitHub org, AI-search abuse

---
*Report generated by Actioner*
