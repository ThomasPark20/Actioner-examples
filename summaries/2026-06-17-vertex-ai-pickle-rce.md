# Pickle in the Middle: Vertex AI SDK Bucket Squatting Cross-Tenant RCE (CVE-2026-2473)

**Date:** 2026-06-17
**Status:** FINAL
**TLP:** WHITE
**CVE:** CVE-2026-2473
**CVSS:** 7.7 (High) -- CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
**CWE:** CWE-340 (Predictability Problems), CWE-345 (Insufficient Verification of Data Authenticity)

---

## Executive Summary

A critical supply chain vulnerability (CVE-2026-2473) in the Google Cloud Vertex AI Python SDK (`google-cloud-aiplatform`) allows cross-tenant remote code execution through a combination of GCS bucket squatting and Python pickle deserialization. Discovered by Ori Hadad of Palo Alto Networks Unit 42, the flaw exploits deterministic bucket naming in the SDK's `stage_local_data_in_gcs()` function. An attacker with their own Google Cloud project can pre-create a victim's staging bucket, intercept model uploads, swap them with malicious pickle payloads, and achieve code execution inside the victim's Vertex AI prediction container. The exfiltrated P4SA OAuth token grants broad `cloud-platform` scope access to other tenant resources including BigQuery datasets, Cloud Logging, and cross-deployment model theft. Google patched the vulnerability in SDK versions 1.144.0 (partial) and 1.148.0 (complete).

---

## Background

The Python `pickle` module is a serialization format that can execute arbitrary code during deserialization. The `__reduce__` dunder method allows objects to define a callable and arguments that reconstruct them upon unpickling -- but this mechanism can be weaponized to invoke `os.system`, `subprocess.Popen`, or other dangerous callables. Libraries like `joblib` (used extensively in scikit-learn ML pipelines) rely on pickle internally, making `joblib.load()` equally dangerous with untrusted data.

Google Cloud's Vertex AI platform allows users to upload, deploy, and serve machine learning models. The `google-cloud-aiplatform` Python SDK provides `Model.upload()` to stage model artifacts in Google Cloud Storage (GCS) before deployment. When users omit the optional `staging_bucket` parameter, the SDK constructs a bucket name deterministically.

GCS bucket names occupy a **globally unique namespace** across all Google Cloud projects. This means an attacker can pre-create a bucket using the victim's predictable name in the attacker's own project -- a technique known as "bucket squatting."

---

## Timeline

| Date | Event |
|------|-------|
| 2026-03-05 | Unit 42 reports vulnerability to Google Cloud VRP |
| 2026-03-09 | Google assigns top priority |
| 2026-03-10 | Google acknowledges and assigns top severity |
| 2026-03-31 | First fix deployed in SDK v1.144.0 (UUID4 randomization of bucket names) |
| 2026-04-15 | Second fix deployed in SDK v1.148.0 (bucket ownership verification) |
| 2026-06-17 | Unit 42 publishes full technical disclosure |

---

## Root Cause

The vulnerability stems from two intersecting design flaws in `gcs_utils.py`:

1. **Deterministic bucket naming:** The function `stage_local_data_in_gcs()` constructs staging bucket names using the pattern `{PROJECT_ID}-vertex-staging-{REGION}` (e.g., `my-project-vertex-staging-us-central1`). Project IDs are often publicly visible or guessable.

2. **Missing ownership verification:** The SDK calls `bucket.exists()` on the constructed name, but this method returns `True` regardless of which project owns the bucket. If the bucket exists (even in another project), the SDK silently uploads model artifacts to it.

The vulnerable code path:

```python
staging_bucket_name = project + "-vertex-staging-" + location
client = storage.Client(project=project, credentials=credentials)
staging_bucket = storage.Bucket(client=client, name=staging_bucket_name)
if not staging_bucket.exists():
    staging_bucket = client.create_bucket(...)
# Uploads proceed to potentially attacker-owned bucket
```

---

## Technical Analysis

### Attack Chain

**Phase 1 -- Bucket Squatting Setup:**
The attacker creates a GCS bucket in their own project matching the victim's predictable naming convention. IAM permissions are configured to grant `allAuthenticatedUsers` the roles `roles/storage.legacyBucketReader`, `roles/storage.objectCreator`, and `roles/storage.objectViewer`. This ensures the victim's SDK can write objects while the attacker retains control.

**Phase 2 -- Payload Preparation:**
The attacker deploys a Cloud Function triggered by the `google.storage.object.finalize` event on the squatted bucket. When any object upload completes, the function replaces the uploaded file with a malicious joblib-serialized payload.

**Phase 3 -- Victim Model Upload:**
The victim calls `Model.upload()` without specifying `staging_bucket`. The SDK resolves the bucket name deterministically, finds the attacker's bucket via `bucket.exists()`, and uploads model artifacts (e.g., `model.joblib`) to the `vertex_ai_auto_staging/` path.

**Phase 4 -- Race Condition Exploitation:**
The timing is critical but feasible:
- **T+0ms:** Victim uploads `model.joblib` (601 bytes)
- **T+804ms:** Attacker's Cloud Function detects the `finalize` event
- **T+1,433ms:** Malicious payload replaces original file (2,945 bytes)
- **T+2,460ms:** Vertex AI's Per-Product Service Account (P4SA) reads the poisoned model

**Phase 5 -- Model Deployment:**
The victim deploys the model to a Vertex AI endpoint via `endpoint.deploy()`. The platform pulls the poisoned artifact from the squatted bucket.

**Phase 6 -- Code Execution:**
The serving container calls `joblib.load()` to deserialize the model. The malicious object's `__reduce__` method executes, running attacker-controlled code with the container's service account identity (`custom-online-prediction@{tenant-project}.iam.gserviceaccount.com`).

### Post-Exploitation

The malicious payload demonstrated in Unit 42's research performs:
1. Queries the GCE metadata server at `metadata.google.internal` for the P4SA OAuth token
2. Collects container environment variables
3. Exfiltrates credentials to an attacker-controlled webhook

The stolen OAuth token carries the broad `cloud-platform` scope, enabling:
- **Cross-deployment model theft** from other model deployments in the same project
- **BigQuery dataset enumeration** and ACL access
- **Cloud Logging access** revealing GKE cluster names, container image URIs, and Kubernetes identities

---

## Indicators of Compromise (IOCs)

### GCS Bucket Patterns (Defanged)

| Type | Value | Context |
|------|-------|---------|
| Bucket Pattern | `{PROJECT_ID}-vertex-staging-{REGION}` | Predictable staging bucket name |
| GCS Path | `vertex_ai_auto_staging/model[.]joblib` | Default model staging path |
| GCS Path | `vertex_ai_auto_staging/model[.]pkl` | Alternate pickle staging path |

### File Artifacts

| Type | Value | Context |
|------|-------|---------|
| File | `model[.]joblib` | Poisoned joblib-serialized model file |
| File | `model[.]pkl` | Poisoned pickle-serialized model file |
| File Size | 601 bytes -> 2,945 bytes | Size change indicating model replacement |

### Network Indicators (Defanged)

| Type | Value | Context |
|------|-------|---------|
| URL | `hxxp://metadata[.]google[.]internal/computeMetadata/v1/instance/service-accounts/` | GCE metadata token theft |
| IP | `169[.]254[.]169[.]254` | Link-local metadata endpoint |
| Header | `Metadata-Flavor: Google` | Required GCE metadata request header |
| API | `storage[.]googleapis[.]com` | GCS API endpoint for bucket operations |

### Service Accounts

| Type | Value | Context |
|------|-------|---------|
| SA Pattern | `custom-online-prediction@{tenant-project}[.]iam[.]gserviceaccount[.]com` | Compromised prediction container identity |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application |
|--------|-----------|-----|-------------|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Attacker intercepts model artifacts via bucket squatting during the software supply chain |
| Execution | Command and Scripting Interpreter: Python | T1059.006 | Malicious pickle `__reduce__` executes Python code in the prediction container |
| Credential Access | Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | Payload queries GCE metadata server for OAuth tokens |
| Discovery | Cloud Infrastructure Discovery | T1580 | Exfiltrated token used to enumerate BigQuery datasets, GKE clusters, Cloud Logging |
| Lateral Movement | Use Alternate Authentication Material: Application Access Token | T1550.001 | Stolen P4SA token with cloud-platform scope enables cross-service access |
| Collection | Data from Cloud Storage | T1530 | Cross-deployment model theft from other GCS-stored models |
| Exfiltration | Exfiltration Over Web Service | T1567 | Credentials exfiltrated to attacker-controlled webhook |

<!-- Revision notes: The following ATT&CK techniques were removed during review:
  - T1059.004 (Unix Shell): No evidence in the PoC of shell spawning; the pickle __reduce__
    invokes Python callables directly (os.system with Python-level commands), not /bin/sh.
  - T1525 (Implant Internal Image): The poisoned model is stored in GCS, not as a container
    image. T1525 applies to container/VM images, not arbitrary cloud storage objects.
  - T1027 (Obfuscated Files or Information): Pickle serialization is a standard format, not
    an obfuscation technique. The malicious code is inherent to pickle's __reduce__ mechanism,
    not deliberately obfuscated.
-->

---

## Impact

- **Severity:** High (CVSS 7.7)
- **Scope:** Any Vertex AI user running vulnerable SDK versions that use deterministic bucket naming. The CVE database lists affected versions as >= 1.21.0 and < 1.133.0. Unit 42's research specifically tested and confirmed exploitation on SDK versions 1.139.0 and 1.140.0, indicating the vulnerable range extends beyond 1.133.0. The complete fix is in SDK v1.148.0; any version prior to that should be considered at risk if the `staging_bucket` parameter is not explicitly set.
- **Affected Product:** `google-cloud-aiplatform` Python SDK
- **Attack Prerequisites:** Attacker needs their own GCP project and knowledge of the victim's project ID (often public). The victim must not have pre-created the staging bucket and must omit the `staging_bucket` parameter.
- **Impact:** Full RCE in prediction container, OAuth token theft with `cloud-platform` scope, cross-tenant data access (BigQuery, Cloud Logging, other model deployments)

---

## Detection & Remediation

### Remediation

1. **Upgrade immediately** to `google-cloud-aiplatform` >= 1.148.0, which includes both UUID4 bucket name randomization and bucket ownership verification.
2. **Always specify `staging_bucket`** explicitly in `Model.upload()` calls, pointing to a bucket you own and control.
3. **Audit existing staging buckets** for unexpected ownership. Run `gsutil ls -L -b gs://{PROJECT_ID}-vertex-staging-{REGION}` and verify the bucket belongs to your project.
4. **Review Cloud Audit Logs** for `storage.objects.create` events on `*-vertex-staging-*` buckets, checking for unusual source projects.
5. **Review deployed models** for unexpected file size changes or modification timestamps that don't match upload times.
6. **Rotate application-level credentials and API keys** if you suspect a staging bucket may have been squatted. Note that the P4SA (Per-Product Service Account) is Google-managed and cannot be directly rotated by users; instead, redeploy affected model endpoints to obtain new P4SA tokens and revoke any previously issued OAuth tokens via the Google Cloud Console.
7. **Enable VPC Service Controls** around Vertex AI and Cloud Storage to restrict cross-project bucket access.

### Detection Opportunities

- Monitor GCS audit logs for object writes to buckets matching `*-vertex-staging-*` where the writer's project differs from the bucket name's project ID prefix.
- Alert on process creation events where a Python process performing model loading (joblib/pickle) spawns shell interpreters or network tools.
- Scan model artifacts (`.pkl`, `.joblib`) with picklescan or similar tools before deployment.

---

## Detection Rules

### Sigma Rules

Two Sigma rules are provided (one GCS audit log rule was cut during review -- see revision notes below).

**Rule 1: Vertex AI Model Upload to Predictable GCS Staging Bucket**
Detects GCS object creation events targeting buckets matching the predictable Vertex AI staging naming convention, combined with model artifact file patterns. This is a broad visibility rule that fires on all default SDK uploads, not just attacks. Triage by correlating the uploading project identity with the bucket name prefix. Uses `|contains` instead of `|re` for broader SIEM backend compatibility. Field names omit the `data.` prefix; custom field mapping may be required depending on your GCP log ingestion pipeline. **Status: PASS** (sigma check exit 0, converted to Splunk and LogScale).

**Rule 2: Pickle Deserialization Leading to Code Execution in ML Model Serving Container**
Detects suspicious child process creation from Python processes involved in model loading or prediction serving. Removed `predict` from ParentCommandLine filter (too broad -- matches any prediction serving process). Consider scoping to Vertex AI container image names if telemetry supports it. **Status: PASS** (sigma check exit 0, converted to Splunk and LogScale).

<!-- REVISION: Sigma Rule 3 (GCE Metadata Server Access from Vertex AI Prediction Container,
     id: 3c5e7f9a-2b4d-6e8f-0a1c-3d5f7b9e1a2c) was CUT during review.
     Reason: The rule title claimed "Vertex AI Prediction Container" scoping but contained
     ZERO container-scoping filters. It would fire on any GCP workload (GCE VM, GKE pod,
     Cloud Function, Cloud Run) accessing the metadata server, which is normal behavior
     for credential acquisition via Application Default Credentials. Extremely high false
     positive rate makes this rule unusable in production. Metadata access monitoring should
     be implemented via container-aware EDR (Falco, Sysdig) or GCP-native audit logging
     with container-level correlation, not generic process_creation rules. -->

```yaml
title: Vertex AI Model Upload to Predictable GCS Staging Bucket
id: 8a3f1c9e-7d2b-4e5a-b6c8-9f0a1d3e5b7c
status: experimental
description: >
  Detects GCS API calls uploading model artifacts to buckets matching the
  predictable Vertex AI staging bucket naming convention. This is a broad
  visibility rule that will fire on all default SDK uploads (not just attacks);
  triage by correlating the uploading project with the bucket name prefix to
  identify cross-project ownership mismatches indicative of bucket squatting
  per CVE-2026-2473. Note: the |re modifier has limited backend support;
  this rule uses |contains instead for broader SIEM compatibility. Field
  names may require custom field mapping depending on your GCP log ingestion
  pipeline (e.g., Elastic, Splunk, or Chronicle).
references:
  - https://unit42.paloaltonetworks.com/hijacking-vertex-ai-model/
  - https://cvereports.com/reports/CVE-2026-2473
  - https://thehackernews.com/2026/06/google-vertex-ai-sdk-flaw-let-attackers.html
author: Actioner CTI
date: 2026-06-17
tags:
  - attack.t1195.002
  - attack.t1059.006
  - cve.2026-2473
logsource:
  product: gcp
  service: gcs
detection:
  selection_bucket_pattern:
    resource.labels.bucket_name|contains: '-vertex-staging-'
  selection_method:
    protoPayload.methodName:
      - 'storage.objects.create'
      - 'storage.objects.insert'
  selection_artifact:
    protoPayload.resourceName|contains:
      - 'model.joblib'
      - 'model.pkl'
      - 'saved_model.pb'
      - 'vertex_ai_auto_staging'
  condition: selection_bucket_pattern and selection_method and selection_artifact
falsepositives:
  - Legitimate Vertex AI model uploads using default SDK staging buckets owned by the same project
  - CI/CD pipelines using older SDK versions with predictable bucket naming
  - Any default SDK upload prior to v1.144.0 will match; cross-reference the uploading principal project against the bucket name prefix to distinguish attacks
level: medium
```

```yaml
title: Pickle Deserialization Leading to Code Execution in ML Model Serving Container
id: 2b4d6e8f-1a3c-5d7e-9f0b-2c4d6a8e0f1a
status: experimental
description: >
  Detects suspicious child process creation from Python processes involved in
  model loading within ML model serving containers. Focuses on joblib and
  pickle deserialization contexts spawning shell interpreters or network
  utilities, indicative of malicious model payloads exploiting CVE-2026-2473.
  Consider scoping to Vertex AI container image names or hostnames if your
  telemetry includes container context.
references:
  - https://unit42.paloaltonetworks.com/hijacking-vertex-ai-model/
  - https://cvereports.com/reports/CVE-2026-2473
author: Actioner CTI
date: 2026-06-17
tags:
  - attack.t1059.006
  - cve.2026-2473
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|endswith:
      - '/python'
      - '/python3'
      - '/python3.10'
      - '/python3.11'
      - '/python3.12'
    ParentCommandLine|contains:
      - 'joblib'
      - 'pickle'
      - 'model_server'
  selection_suspicious_child:
    Image|endswith:
      - '/sh'
      - '/bash'
      - '/curl'
      - '/wget'
      - '/nc'
      - '/ncat'
      - '/python'
      - '/python3'
  condition: selection_parent and selection_suspicious_child
falsepositives:
  - Model preprocessing scripts that legitimately invoke shell commands
  - Custom prediction routines with shell-based data transformations
level: medium
```

### YARA Rules

Three YARA rules are provided, unchanged from draft (all passed review).

**Rule 1: Malicious_Pickle_Reduce_Exec**
Detects pickle files containing protocol headers combined with REDUCE opcodes and dangerous module references (os.system, subprocess, builtins.exec). Generic pickle malware detector, not CVE-specific. Note: `$reduce_opcode = { 52 }` is a single-byte match that is cosmetic in the context of the full condition but may produce yarac warnings. **Status: PASS** (yarac exit 0, warnings about short hex string are expected and non-blocking).

**Rule 2: Malicious_Joblib_Pickle_Payload**
Detects joblib-serialized files containing dangerous callables combined with GCE metadata theft indicators, targeting the specific post-exploitation pattern from CVE-2026-2473. Most CVE-specific rule in the set. Renamed `$numpy_marker` comment to `$numpy_array_header` for clarity. **Status: PASS** (yarac exit 0).

**Rule 3: Pickle_GCE_Metadata_Token_Theft**
Detects pickle payloads crafted specifically to steal GCE metadata service OAuth tokens, matching the exact exfiltration technique described in the Unit 42 research. Same single-byte `$reduce` caveat as Rule 1. **Status: PASS** (yarac exit 0, warnings about short hex string are expected and non-blocking).

```yara
rule Malicious_Pickle_Reduce_Exec
{
    meta:
        description = "Detects Python pickle payloads using __reduce__ to invoke os.system, subprocess, or exec for code execution. Generic pickle malware detector applicable to model poisoning attacks like CVE-2026-2473. Note: $reduce_opcode is a single-byte match (0x52) which is cosmetic in combination with the other conditions but may generate warnings in some YARA implementations."
        author = "Actioner CTI"
        date = "2026-06-17"
        reference = "https://unit42.paloaltonetworks.com/hijacking-vertex-ai-model/"
        severity = "medium"
        tlp = "white"

    strings:
        $pickle_magic_v2 = { 80 02 }
        $pickle_magic_v3 = { 80 03 }
        $pickle_magic_v4 = { 80 04 }
        $pickle_magic_v5 = { 80 05 }
        $reduce_opcode = { 52 }  // REDUCE opcode - single byte, cosmetic in this context
        $os_system = "os\nsystem" ascii
        $os_popen = "os\npopen" ascii
        $subprocess_call = "subprocess\ncall" ascii
        $subprocess_popen = "subprocess\nPopen" ascii
        $subprocess_check_output = "subprocess\ncheck_output" ascii
        $builtins_exec = "builtins\nexec" ascii
        $builtins_eval = "builtins\neval" ascii
        $posix_system = "posix\nsystem" ascii
        $nt_system = "nt\nsystem" ascii
        $commands_getoutput = "commands\ngetoutput" ascii
        $builtins_getattr = "builtins\ngetattr" ascii

    condition:
        (any of ($pickle_magic_*)) and
        $reduce_opcode and
        (any of ($os_system, $os_popen, $subprocess_call, $subprocess_popen,
                 $subprocess_check_output, $builtins_exec, $builtins_eval,
                 $posix_system, $nt_system, $commands_getoutput, $builtins_getattr))
}

rule Malicious_Joblib_Pickle_Payload
{
    meta:
        description = "Detects joblib-serialized files containing suspicious pickle reduce calls, targeting model poisoning in ML pipelines such as the Vertex AI bucket squatting attack (CVE-2026-2473)."
        author = "Actioner CTI"
        date = "2026-06-17"
        reference = "https://unit42.paloaltonetworks.com/hijacking-vertex-ai-model/"
        severity = "medium"
        tlp = "white"

    strings:
        $joblib_marker = "joblib" ascii
        $numpy_array_header = { 93 4E 55 4D 50 59 }  // NumPy array .npy magic bytes (0x93 + "NUMPY")
        $os_system = "os\nsystem" ascii
        $os_popen = "os\npopen" ascii
        $subprocess_call = "subprocess\ncall" ascii
        $subprocess_popen = "subprocess\nPopen" ascii
        $builtins_exec = "builtins\nexec" ascii
        $builtins_eval = "builtins\neval" ascii
        $posix_system = "posix\nsystem" ascii
        $metadata_url = "metadata.google.internal" ascii
        $compute_metadata = "computeMetadata" ascii
        $service_accounts = "service-accounts" ascii

    condition:
        ($joblib_marker or $numpy_array_header) and
        (any of ($os_system, $os_popen, $subprocess_call, $subprocess_popen,
                 $builtins_exec, $builtins_eval, $posix_system)) and
        (any of ($metadata_url, $compute_metadata, $service_accounts))
}

rule Pickle_GCE_Metadata_Token_Theft
{
    meta:
        description = "Detects pickle payloads specifically crafted to steal GCE metadata service OAuth tokens, a key post-exploitation step in the Vertex AI cross-tenant RCE attack chain. Note: $reduce is a single-byte match (0x52) which is cosmetic in combination with the other conditions but may generate warnings in some YARA implementations."
        author = "Actioner CTI"
        date = "2026-06-17"
        reference = "https://unit42.paloaltonetworks.com/hijacking-vertex-ai-model/"
        severity = "medium"
        tlp = "white"

    strings:
        $pickle_v2 = { 80 02 }
        $pickle_v3 = { 80 03 }
        $pickle_v4 = { 80 04 }
        $pickle_v5 = { 80 05 }
        $metadata1 = "metadata.google.internal" ascii
        $metadata2 = "169.254.169.254" ascii
        $token_path = "computeMetadata/v1/instance/service-accounts" ascii
        $header = "Metadata-Flavor" ascii
        $reduce = { 52 }  // REDUCE opcode - single byte, cosmetic in this context

    condition:
        (any of ($pickle_v*)) and
        $reduce and
        (any of ($metadata1, $metadata2)) and
        ($token_path or $header)
}
```

### Suricata Rules

Two Suricata rules are provided (one rule was cut during review -- see revision notes below).

**Rule 1: ETPRO EXPLOIT Vertex AI Staging Bucket Model Upload**
Detects HTTP POST requests to `storage.googleapis.com` with URI containing `vertex-staging` and model file extensions. **Prerequisite:** Requires TLS inspection (SSL/TLS decryption) to see HTTPS traffic to GCS; without it, this rule will not fire on production traffic. False positives include all legitimate SDK uploads using default bucket naming. Note: this rule does not cover bucket-subdomain style URLs (`BUCKET.storage.googleapis.com`); a companion rule may be needed. **Status: PASS** (suricata -T exit 0).

<!-- REVISION: Suricata Rule 2 (GCE Metadata Token Access from Prediction Container,
     sid:1000002) was CUT during review.
     Reason: Same issue as Sigma Rule 3 -- the rule fired on ALL HTTP requests to
     169.254.169.254 with Metadata-Flavor headers, which is standard behavior for
     every GCP workload using Application Default Credentials. Suricata has no
     container-scoping capability, making this rule unusable in production GCP
     environments. Metadata access monitoring should use container-aware EDR or
     GCP-native audit logging instead. -->

**Rule 3: ETPRO EXPLOIT Suspected OAuth Token Exfiltration Post Pickle Deserialization**
Detects outbound HTTP POST requests with JSON bodies containing `access_token` and `cloud-platform`, indicating exfiltration of stolen GCE OAuth tokens. **Prerequisite:** Requires TLS inspection to inspect HTTPS POST bodies; without it, only plaintext HTTP exfiltration will be detected. **Deployment note:** Ensure `stream.reassembly.depth` is configured adequately (default 1MB should suffice) for full POST body reassembly. **Status: PASS** (suricata -T exit 0).

```
# Rule 1: Vertex AI Staging Bucket Model Upload
# REQUIRES TLS INSPECTION. See deployment notes above.
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO EXPLOIT Vertex AI Staging Bucket Model Upload - Possible Bucket Squatting (CVE-2026-2473)"; flow:established,to_server; http.method; content:"POST"; http.host; content:"storage.googleapis.com"; http.uri; content:"vertex-staging"; content:"upload"; pcre:"/\.(pkl|joblib|pickle|pb)(\?|$)/"; reference:url,unit42.paloaltonetworks.com/hijacking-vertex-ai-model/; reference:cve,2026-2473; classtype:attempted-admin; sid:1000001; rev:2;)

# Rule 3: Suspected OAuth Token Exfiltration
# REQUIRES TLS INSPECTION. Ensure stream.reassembly.depth >= 1MB.
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO EXPLOIT Suspected OAuth Token Exfiltration Post Pickle Deserialization (CVE-2026-2473)"; flow:established,to_server; http.method; content:"POST"; http.header; content:"Content-Type"; content:"application/json"; http.request_body; content:"access_token"; content:"cloud-platform"; reference:url,unit42.paloaltonetworks.com/hijacking-vertex-ai-model/; reference:cve,2026-2473; classtype:trojan-activity; sid:1000003; rev:2;)
```

---

## Revision Summary

This report was revised from DRAFT to FINAL based on peer review feedback. The following changes were made:

### Rules Cut (2)
1. **Sigma Rule 3** (GCE Metadata Server Access from Vertex AI Prediction Container, id: `3c5e7f9a-2b4d-6e8f-0a1c-3d5f7b9e1a2c`): Cut due to zero container-scoping filters. Would fire on all GCP workloads using default credentials. Metadata monitoring should use container-aware EDR or GCP audit logs.
2. **Suricata Rule 2** (GCE Metadata Token Access from Prediction Container, sid: `1000002`): Cut for the same reason -- Suricata cannot scope to containers, making the rule fire on all metadata access across the environment.

### Rules Revised (3)
1. **Sigma Rule 1**: Retitled from "Suspicious Vertex AI Model Upload" to "Vertex AI Model Upload to Predictable GCS Staging Bucket" to reflect broad visibility scope. Replaced `|re` with `|contains` for backend compatibility. Removed `data.` prefix from field names (was incorrect for raw GCP audit logs). Added documentation about custom field mapping requirements and FP triage guidance.
2. **Sigma Rule 2**: Removed `predict` from `ParentCommandLine|contains` (too broad -- matches any prediction process). Removed `attack.t1027` tag (pickle is not obfuscation). Removed `attack.t1059.004` tag (no shell spawning evidence in PoC). Added note about container scoping.
3. **Suricata Rule 1**: Added TLS inspection prerequisite documentation. Added FP note about legitimate SDK uploads. Added note about missing bucket-subdomain URL style coverage. Bumped rev to 2.
4. **Suricata Rule 3**: Added TLS inspection prerequisite documentation. Added `stream.reassembly.depth` deployment note. Bumped rev to 2.

### YARA Rules (no functional changes)
- YARA Rule 2: Renamed `$numpy_marker` to `$numpy_array_header` for comment clarity.
- All three rules: Added documentation in meta descriptions noting single-byte `$reduce` opcode caveats.

### Report-Level Fixes
1. **CWE**: Added CWE-345 (Insufficient Verification of Data Authenticity) alongside CWE-340, reflecting the missing bucket ownership verification.
2. **Version scope**: Reconciled the contradiction between "< 1.133.0" (CVE database) and tested versions 1.139.0/1.140.0 (Unit 42). The Impact section now explains both data points and recommends treating all versions prior to 1.148.0 as vulnerable.
3. **ATT&CK mapping**: Removed T1525 (Implant Internal Image -- model in GCS is not a container image), T1027 (Obfuscated Files -- pickle is not obfuscation), and T1059.004 (Unix Shell -- no evidence of shell spawning in PoC). Revision notes explain each removal.
4. **Remediation item 6**: Clarified that P4SA is Google-managed and cannot be directly rotated by users. Updated guidance to recommend redeploying model endpoints and revoking OAuth tokens instead.
5. **Detection Opportunities**: Removed metadata server monitoring bullet (covered by cut rules; should use container-aware tooling instead).
6. **Status**: Changed from DRAFT to FINAL.

---

## Standalone Rule Files

| Format | Path |
|--------|------|
| Sigma | `rules/sigma/2026-06-17-vertex-ai-pickle-rce.yml` |
| YARA | `rules/yara/2026-06-17-vertex-ai-pickle-rce.yar` |
| Suricata | `rules/suricata/2026-06-17-vertex-ai-pickle-rce.rules` |

---

## Sources

1. [Pickle in the Middle -- Hijacking Vertex AI Model Uploads for Cross-Tenant RCE (Unit 42)](https://unit42.paloaltonetworks.com/hijacking-vertex-ai-model/) -- Primary research by Ori Hadad, Palo Alto Networks Unit 42.
2. [CVE-2026-2473: Bucket Squatting on Google Vertex AI (CVEReports)](https://cvereports.com/reports/CVE-2026-2473) -- CVE entry with CVSS 7.7, CWE-340 classification.
3. [Google Vertex AI SDK Flaw Let Attackers Hijack Model Uploads via Bucket Squatting (The Hacker News)](https://thehackernews.com/2026/06/google-vertex-ai-sdk-flaw-let-attackers.html) -- Coverage including remediation guidance and timeline.
4. [Kicking the Bucket: Critical RCE and Cross-Tenant Exploits in 3 Different GCP Products (Focal Security)](https://focalsecurity.io/blog/kicking-the-bucket-gcp-cross-tenant/) -- Related GCP bucket squatting research providing broader context on the attack class.
5. [googleapis/python-aiplatform Releases (GitHub)](https://github.com/googleapis/python-aiplatform/releases) -- Official SDK release notes for patched versions.
