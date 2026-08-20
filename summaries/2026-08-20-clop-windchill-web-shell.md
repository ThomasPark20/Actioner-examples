# Technical Analysis Report: Clop Windchill Custom Web Shell Campaign (2026-08-20)

Prepared by: Actioner
Classification: TLP:CLEAR
Date: 2026-08-20
Version: 1.0 FINAL

<!-- audit: primary sources fetched 3/3 (CyberScoop 200, THN 200, SecurityWeek 200); deeper sources fetched 4/7 (ReliaQuest 200, BleepingComputer 200, SecurityBrief 200, CybersecurityNews 200; PTC advisory 403, Ransom-ISAC 403, TechNadu 403); total qualifying sources: 7; sigma check blocked by proxy (MITRE ATT&CK data fetch 403), sigma convert --without-pipeline -t splunk: 5/5 pass, sigma convert --without-pipeline -t log_scale: 5/5 pass; yarac: pass on attempt 2 (fixed unreferenced $gzip_enc string); snort/suricata: uncompiled (not installed) -->
<!-- revision: v0.1->v1.0 per critic verdict NEEDS-REVISION. Changes: (1) Sigma #3 credential-decryption downgraded to low, relabeled as hunt/correlation-only, noted Windows-only scope gap, removed T1003 tag; (2) Sigma #4 vault-enum downgraded from high to medium, noted Windows-only scope gap and generic filename risk; (3) Sigma #5 C2-IPs added missing IP 5.180.41.35 (now 7 IPs), prose corrected six->seven; (4) YARA meta rewritten to state hashes are reference-only (not in condition), high-confidence tier raised to 4-of-5 or 3-of-5+cmd_header; (5) Snort SIDs 2100201-2100203 confidence downgraded one tier each (medium/low/medium); (6) Suricata SIDs 2200201-2200203 confidence downgraded one tier each (medium/low/medium); (7) T1003 removed from MITRE ATT&CK mapping. Re-validation: sigma convert splunk/logscale 3/3 pass, yarac pass. -->

## Executive Summary

Clop (Cl0p), the financially motivated ransomware and extortion group, has deployed a purpose-built JSP web shell against PTC Windchill product lifecycle management (PLM) servers in a mass-extortion campaign exploiting CVE-2026-12569 (CVSS 9.3). Unlike the generic web shells observed during the initial June 2026 exploitation wave, this custom implant was engineered with detailed knowledge of Windchill's internal APIs, database schema, keystore mechanisms, and file-vault architecture. The web shell decrypts every credential in the Windchill keystore, maps engineering vault data for targeted exfiltration, and includes a custom Java class loader for arbitrary in-memory code execution. Over 40 victim organizations have been named on Clop's extortion site, including Shell, Philips, Fiserv, Zebra Technologies, and Ingersoll Rand. Stolen data spans engineering blueprints, CAD files, product databases, and corporate documents, with per-victim volumes ranging from 1 GB to multiple terabytes.

This report supplements the existing CVE-2026-12569 coverage (2026-06-27/28) with analysis of the new web shell artifacts, additional C2 infrastructure, and updated detection rules targeting the implant's distinctive behaviors.

## Background

PTC Windchill is the industry-standard product lifecycle management platform used across automotive, aerospace, defense, medical devices, and manufacturing sectors to manage engineering data, bills of materials, change processes, and product documentation. FlexPLM extends Windchill into fashion and retail product lifecycle management. Both products share the vulnerable code path exploited by CVE-2026-12569.

Clop has an established pattern of mass-exploiting enterprise file transfer and collaboration platforms using custom-built web shells. Previous campaigns targeted Accellion FTA (DEWMODE shell, 2021), GoAnywhere MFT (2023), MOVEit Transfer (LEMURLOOT shell, 2023), Cleo (2024), and Oracle E-Business Suite. The Windchill campaign follows the same playbook: identify a zero-day in widely deployed enterprise software, build a bespoke implant that understands the target application's data model, and execute mass exploitation followed by data theft and extortion.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-06-17 | PTC discloses CVE-2026-12569 and begins issuing patches |
| 2026-06-18 | PTC publishes first IOC set for customers |
| ~2026-06-20 | Mass exploitation begins; generic JSP web shells deployed |
| 2026-06-25 | CISA adds CVE-2026-12569 to Known Exploited Vulnerabilities catalog |
| 2026-06-25 | German authorities warn organizations of imminent attacks |
| Late July | Custom Clop web shell identified by ReliaQuest in active incidents |
| Mid-July | Clop sends threatening extortion emails to victims |
| 2026-08-12 | Clop begins publishing victim names on extortion site |
| 2026-08-19 | ReliaQuest publishes detailed web shell analysis |

## Technical Analysis

### 1. Exploitation Chain

CVE-2026-12569 is an improper input validation vulnerability (CWE-20) in PTC Windchill and FlexPLM that allows unauthenticated remote code execution. The attack chains a pre-authentication information disclosure flaw in the FlexPLM WSDL endpoint with a server-side vulnerability in the Windchill login servlet. An attacker sends a specially crafted HTTP request to achieve arbitrary code execution without authentication or user interaction (CVSS AV:N/AC:L/PR:N/UI:N).

### 2. Custom Web Shell Architecture

The Clop implant is a JavaServer Pages (JSP) file designed specifically for the Windchill application environment. It is not a generic web shell repurposed for the campaign -- it was built with intimate knowledge of Windchill's internal APIs, database schema, keystore infrastructure, and file-vault layout.

**Deployment location:** Web shells are dropped under `/Windchill/codebase/login/` within the application's deployed directory structure.

**Naming conventions observed:**
- 16-character lowercase hexadecimal: `/Windchill/login/[0-9a-f]{16}.jsp`
- 6-character hexadecimal: `/Windchill/login/[0-9a-fA-F]{6}.jsp`
- DPR prefix with 8-hex suffix: `/Windchill/login/dpr_[0-9a-fA-F]{8}.jsp`

**Known hashes (SHA-256):**
- `321e1fb01eb3462b48ff6ccdef132acc1182e3f7456548439f0d4ead12fd98bf` (custom Clop implant, August 2026)
- `55a1eb4c2d3da04376df39d7ba832569c6af1a37a0cf2b95f754ac898023a30c` (earlier variant, June 2026)

### 3. Command Dispatch Protocol

Commands are transmitted via the custom HTTP header `X-windchill-req` rather than visible request body parameters. The header value is eight characters, with the first character specifying the command. Responses are GZIP-compressed, reducing visibility for defenses that do not decrypt TLS traffic and inspect compressed content.

The web shell implements eight operational commands:

| Command | Function | Description |
|---------|----------|-------------|
| **S** | Credential extraction | Reads `ieStructProperties.txt`, decrypts LDAP manager password from application keystore using `WTKeyStoreUtil.decryptProperty()`, iterates through stored properties decrypting additional encrypted values. Returns Windchill administrative credentials in plaintext via the "gs" function. |
| **L** | Vault enumeration | Maps the file vault by querying database tables (`ApplicationData`, `FVITEM`, `FVMOUNT`, `MasteredOnReplicaItem`). Outputs vault stream IDs, filenames, storage paths, and file sizes to `flst.txt` via the "fl" function and `Flst1` class. |
| **D** | Directory enumeration | Enumerates directories and reads file portions for reconnaissance. |
| **G** | File retrieval | Retrieves complete file contents for exfiltration. |
| **R** | File deletion | Deletes specified files (anti-forensics/cleanup). |
| **J** | Java class loading | Loads compiled Java bytecode from a Base64-encoded ZIP payload directly into memory and executes it. No disk artifacts created. Custom class loader enables arbitrary code execution within the application process. |
| **O** | OS identification | Returns operating system identification information. |
| **E** | Echo/keepalive | Echo verification function for connectivity testing. |

### 4. Credential Decryption Mechanism

The "S" command is the most consequential capability. The "gs" function:

1. Reads the `ieStructProperties.txt` configuration file containing encrypted property references
2. Accesses the Windchill keystore and decrypts the LDAP directory manager password using `WTKeyStoreUtil.decryptProperty()`
3. Iterates through all stored local properties, decrypting any encrypted values

This extraction yields directory-management and administrative credentials including:
- LDAP directory manager passwords (Active Directory, LDAP services)
- Storage access keys
- Site administrator credentials
- Email system credentials
- VPN credentials

This transforms a single-host Windchill compromise into an enterprise-wide identity compromise affecting Active Directory, email, VPN, and any service whose credentials are stored in the Windchill keystore.

### 5. Vault Mapping and Data Staging

The "L" command uses the `Flst1` class to execute SQL queries against Windchill's database using the application's own database identity (via `WTConnection`). The queries target:

- `ApplicationData` -- application metadata
- `FVITEM` -- file vault items
- `FVMOUNT` -- vault mount points
- `MasteredOnReplicaItem` -- replication metadata

Results are written to `flst.txt`, producing a complete inventory of vault contents including stream IDs, filenames, storage paths, and file sizes. This inventory enables targeted exfiltration of high-value engineering data rather than blind bulk theft.

### 6. In-Memory Code Execution

The "J" command accepts a Base64-encoded ZIP file containing compiled Java bytecode. The custom Java class loader executes this code entirely in memory within the Windchill application process, creating no disk artifacts. This extends the web shell into an unlimited backdoor capable of:
- Lateral movement using stolen credentials
- Additional data exfiltration
- Ransomware deployment
- Persistence mechanism installation

### 7. Evasion Techniques

- **Application blending:** The shell uses Windchill's native database connections and internal Java classes (`MethodContext`, `WTConnection`, `WTKeyStoreUtil`), making queries appear to originate from the legitimate Windchill service identity rather than from a separate attacker account.
- **Custom header C2:** The `X-windchill-req` header avoids detection by WAFs and log analyzers that inspect request bodies but not custom headers.
- **GZIP compression:** Response compression reduces payload visibility in network monitoring.
- **Hex-named files:** Randomized hexadecimal filenames avoid predictable patterns; placement in the legitimate `/Windchill/login/` directory blends with application resources.

### 8. Data Exfiltration

Stolen data types confirmed across victims include:
- Engineering documents and blueprints
- CAD diagrams and product designs
- Product databases
- Project files and backups
- Corporate documents
- Photographs and logs

Per-victim theft volumes range from 1 GB to multiple terabytes.

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All network IOCs use defanged notation. Detection rule values use real (non-defanged) notation.

### File System

| Indicator | Type | Context |
|-----------|------|---------|
| `/Windchill/login/[0-9a-f]{16}.jsp` | Path pattern | Web shell (16-hex naming) |
| `/Windchill/login/[0-9a-fA-F]{6}.jsp` | Path pattern | Web shell (6-hex naming) |
| `/Windchill/login/dpr_[0-9a-fA-F]{8}.jsp` | Path pattern | Web shell (dpr_ prefix naming) |
| `321e1fb01eb3462b48ff6ccdef132acc1182e3f7456548439f0d4ead12fd98bf` | SHA-256 | Custom Clop web shell (August 2026) |
| `55a1eb4c2d3da04376df39d7ba832569c6af1a37a0cf2b95f754ac898023a30c` | SHA-256 | Earlier web shell variant (June 2026) |
| `flst.txt` | Filename | Vault enumeration output file |
| `ieStructProperties.txt` | Filename | Windchill configuration file read during credential decryption |

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `5.180.41[.]35` | Primary C2 (also in June 2026 campaign) |
| IP | `78.128.113[.]10` | C2 infrastructure (August 2026) |
| IP | `104.194.9[.]14` | C2 infrastructure (August 2026) |
| IP | `104.243.35[.]63` | C2 infrastructure (August 2026) |
| IP | `185.227.83[.]236` | C2 infrastructure (August 2026) |
| IP | `209.222.98[.]44` | C2 infrastructure (August 2026) |
| IP | `216.152.151[.]204` | C2 infrastructure (August 2026) |
| HTTP Header | `X-windchill-req` | Command dispatch header |
| URL Pattern | `POST /Windchill/login/dpr_[hex].jsp` | Web shell C2 communication |
| URL Pattern | `POST /Windchill/login/[6-hex].jsp` | Web shell C2 communication |

### Behavioral

- POST requests to `/Windchill/login/*.jsp` with dynamically generated filenames
- Presence of `X-windchill-req` header in HTTP requests to Windchill endpoints
- GZIP-compressed HTTP responses from JSP endpoints under `/Windchill/login/`
- Creation of `flst.txt` by a Java process
- Access to `ieStructProperties.txt` from the web application context
- Java process referencing `WTKeyStoreUtil`, `WTConnection`, or `MethodContext` classes in unexpected contexts

### Web Shell Internal Strings (for YARA/file scanning)

- `WTKeyStoreUtil`
- `WTConnection`
- `MethodContext`
- `decryptProperty`
- `ieStructProperties`
- `Flst1`
- `flst.txt`
- `X-windchill-req`
- `GZIPOutputStream`

## MITRE ATT&CK Mapping

| Technique ID | Name | Context |
|-------------|------|---------|
| T1190 | Exploit Public-Facing Application | Initial access via CVE-2026-12569 RCE |
| T1505.003 | Server Software Component: Web Shell | Custom JSP web shell deployment |
| T1555 | Credentials from Password Stores | Keystore credential decryption via WTKeyStoreUtil |
| T1140 | Deobfuscate/Decode Files or Information | Credential decryption from encrypted keystore |
| T1083 | File and Directory Discovery | Vault enumeration (L command), directory listing (D command) |
| T1005 | Data from Local System | Engineering data staging and theft |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP-based C2 via X-windchill-req header |
| T1620 | Reflective Code Loading | In-memory Java class loader (J command) |
| T1070.004 | Indicator Removal: File Deletion | File cleanup capability (R command) |
| T1560 | Archive Collected Data | GZIP compression of exfiltrated data |
| T1041 | Exfiltration Over C2 Channel | Data theft over HTTP |

## Impact

### Named Victims (40+)

Clop has named over 40 victim organizations on its extortion site. Confirmed names include:
- **Shell** (energy)
- **Philips** (medical devices/electronics)
- **Fiserv** (financial technology)
- **Zebra Technologies** (enterprise technology)
- **Ingersoll Rand** (industrial manufacturing)
- **Toast** (restaurant technology)
- **Mindray** (medical devices)
- **Largan Precision** (optical components)
- **GE** (conglomerate; later removed from list)

### Sector Impact

Windchill is predominantly deployed in sectors where product data constitutes core intellectual property:
- Aerospace and defense
- Automotive manufacturing
- Medical device manufacturing
- Heavy machinery and industrial equipment
- Electronics and semiconductor

Compromise of engineering vaults in these sectors exposes trade secrets, product designs, manufacturing processes, and potentially export-controlled technical data.

## Detection & Remediation

### Immediate Actions

1. **Patch CVE-2026-12569** -- apply PTC-provided patches for all Windchill and FlexPLM instances immediately
2. **Hunt for web shells** -- search for unexpected JSP files under `/Windchill/codebase/login/` with recent modification timestamps, particularly files matching the hex or dpr_ naming patterns
3. **Block C2 IPs** -- add the seven identified C2 IP addresses to firewall blocklists
4. **Scan for IOC hashes** -- search endpoints for the two known web shell SHA-256 hashes
5. **Check for flst.txt** -- search for `flst.txt` in `/tmp`, Windchill working directories, and web application directories
6. **Rotate credentials** -- if compromise is confirmed, rotate all credentials stored in the Windchill keystore, including LDAP, Active Directory, email, VPN, and storage credentials
7. **Review web server logs** -- search for POST requests to `/Windchill/login/` targeting dynamically named JSP files, and for the `X-windchill-req` header (requires custom header logging)
8. **Inspect for `ieStructProperties.txt` access** -- check file access logs for unexpected reads of this configuration file

### Detection Engineering

- **Enable custom header logging** -- default web server configurations do not log arbitrary request headers; enable logging for `X-windchill-req` specifically
- **Deploy YARA rules** -- scan Windchill codebase directories with the provided YARA rule targeting Windchill-specific internal API strings
- **Network monitoring** -- deploy Suricata/Snort rules to detect the dpr_ and short-hex POST patterns and the X-windchill-req header in HTTP traffic
- **File integrity monitoring** -- alert on new JSP file creation under Windchill application directories

## Detection Rules

### Sigma Rules

<!-- audit: sigma check blocked by proxy (MITRE ATT&CK data URL 403); sigma convert --without-pipeline -t splunk: 5/5 pass (re-validated 3 changed rules); sigma convert --without-pipeline -t log_scale: 5/5 pass (re-validated 3 changed rules) -->

#### 1. Clop Windchill Web Shell POST - DPR Naming Pattern
Detects POST requests to JSP files with the dpr_[hex]{8}.jsp naming convention in the Windchill login directory, a pattern specific to the August 2026 Clop campaign.
- **File:** `rules/sigma/2026-08-20-clop-windchill-webshell-dpr-post.yml`
- **Status:** compile:splunk-pass, compile:logscale-pass | confidence:high
- **Caveat:** Requires web access log ingestion with URI stem field.

#### 2. Clop Windchill Web Shell POST - Short Hex Naming Pattern
Detects POST requests to JSP files with 6-character hexadecimal filenames under the Windchill login path.
- **File:** `rules/sigma/2026-08-20-clop-windchill-webshell-short-hex-post.yml`
- **Status:** compile:splunk-pass, compile:logscale-pass | confidence:medium
- **Caveat:** Shorter hex pattern has marginally higher false-positive potential than 16-hex or dpr_ patterns.

#### 3. Clop Windchill Web Shell Credential Decryption Activity (Hunt Query)
Correlation-only / hunt rule. Detects file access to ieStructProperties.txt by a Java process. Windchill's own Java process reads this file during normal startup and configuration reload, so this rule fires on routine application behavior. Use only in correlation with other Clop Windchill indicators.
- **File:** `rules/sigma/2026-08-20-clop-windchill-webshell-credential-decryption.yml`
- **Status:** compile:splunk-pass, compile:logscale-pass | confidence:low
- **Caveat:** High false-positive rate from legitimate Windchill operations. Windows-only scope (Windchill commonly runs on Linux).

#### 4. Clop Windchill Web Shell Vault Enumeration Output
Detects creation of flst.txt by a Java process, indicating the vault enumeration function of the Clop web shell. The filename "flst.txt" is generic enough to be created by other Java-based tools; correlate with additional indicators before escalating.
- **File:** `rules/sigma/2026-08-20-clop-windchill-webshell-vault-enum.yml`
- **Status:** compile:splunk-pass, compile:logscale-pass | confidence:medium
- **Caveat:** Requires Sysmon or equivalent file event logging on Windchill servers. Windows-only scope (Windchill commonly runs on Linux).

#### 5. Clop Windchill Campaign C2 Infrastructure Communication
Detects outbound connections to seven IP addresses associated with the August 2026 Clop Windchill campaign infrastructure.
- **File:** `rules/sigma/2026-08-20-clop-windchill-webshell-c2-ips.yml`
- **Status:** compile:splunk-pass, compile:logscale-pass | confidence:high
- **Caveat:** IP-based detections have a limited shelf life; IPs may be rotated or reused for legitimate services.

### YARA Rule

<!-- audit: yarac attempt 1 failed (unreferenced $gzip_enc string); yarac attempt 2 pass; revision yarac re-validated pass (meta corrected, high-confidence tier raised to 4-of-5 or 3-of-5+cmd_header) -->

#### 6. Clop Windchill Custom Web Shell (August 2026)
Targets the Windchill-specific internal API strings (WTKeyStoreUtil, WTConnection, MethodContext, ieStructProperties, Flst1) and X-windchill-req command header that distinguish this implant from generic JSP web shells. Hashes in meta are reference-only and are not used in the condition; detection relies entirely on string matching.
- **File:** `rules/yara/2026-08-20-clop-windchill-custom-webshell.yar`
- **Status:** compile:yarac-pass | confidence:high (4+ Windchill API strings, or 3+ with cmd_header), medium (cmd_header + vault/cred/gzip combination)
- **Caveat:** String-based detection only (no hash matching in condition). Windchill-specific strings may appear in legitimate Windchill source files; triage matches with file location and context.

### Snort Rules

<!-- audit: snort not installed; structural review only -->

#### 7-9. Clop Windchill Web Shell Network Detection (Snort)
Three rules detecting: (a) POST to dpr_-prefixed JSP, (b) POST to 6-hex-character JSP, (c) X-windchill-req header in POST to Windchill.
- **File:** `rules/snort/2026-08-20-clop-windchill-webshell.rules`
- **Status:** uncompiled | confidence:medium (SID 2100201 dpr_ pattern), low (SID 2100202 short hex), medium (SID 2100203 X-windchill-req header)
- **SIDs:** 2100201, 2100202, 2100203
- **Caveat:** Uncompiled rules -- confidence downgraded one tier from compiled equivalents. Requires TLS decryption to inspect HTTPS traffic to Windchill servers.

### Suricata Rules

<!-- audit: suricata not installed; structural review only -->

#### 10-12. Clop Windchill Web Shell Network Detection (Suricata)
Three rules with identical logic using Suricata dot-notation sticky buffers (http.method, http.uri, http.header_names).
- **File:** `rules/suricata/2026-08-20-clop-windchill-webshell.rules`
- **Status:** uncompiled | confidence:medium (SID 2200201 dpr_ pattern), low (SID 2200202 short hex), medium (SID 2200203 X-windchill-req header)
- **SIDs:** 2200201, 2200202, 2200203
- **Caveat:** Uncompiled rules -- confidence downgraded one tier from compiled equivalents. Requires TLS decryption to inspect HTTPS traffic to Windchill servers.

## Sources

1. [CyberScoop - Clop zero-day attacks PTC Windchill FlexPLM](https://cyberscoop.com/clop-zero-day-attacks-ptc-windchill-flexplm/)
2. [The Hacker News - Clop-Linked Windchill Web Shell Decrypts Credentials and Maps Engineering Data](https://thehackernews.com/2026/08/clop-linked-windchill-web-shell.html)
3. [SecurityWeek - Cl0p Ransomware Group Names Over 40 Victims of PTC Windchill Campaign](https://www.securityweek.com/cl0p-ransomware-group-names-over-40-victims-of-ptc-windchill-campaign/)
4. [ReliaQuest - Clop Returns with Custom Implant in Mass-Extortion Campaign](https://reliaquest.com/blog/clop-returns-with-custom-implant-in-mass-extortion-campaign)
5. [BleepingComputer - Clop created custom web shell for Windchill data theft attacks](https://www.bleepingcomputer.com/news/security/clop-created-custom-web-shell-for-windchill-data-theft-attacks/)
6. [SecurityBrief - Clop-linked web shell hits Windchill in new exploit](https://securitybrief.co.uk/story/clop-linked-web-shell-hits-windchill-in-new-exploit)
7. [CybersecurityNews - Cl0p Hackers Exploit PTC Windchill Flaw to Steal Passwords](https://cybersecuritynews.com/cl0p-hackers-exploit-ptc/)
