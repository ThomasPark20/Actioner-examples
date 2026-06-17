# Pickle in the Middle: Vertex AI SDK Bucket Squatting Cross-Tenant RCE (CVE-2026-2473)

**Date:** 2026-06-17
**Status:** DRAFT
**TLP:** WHITE
**CVE:** CVE-2026-2473
**CVSS:** 7.7 (High) -- CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
**CWE:** CWE-340 (Predictability Problems)

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
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Pickle payload spawns shell commands for data collection |
| Persistence | Implant Internal Image | T1525 | Poisoned model persists across container restarts as it is served from GCS |
| Credential Access | Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | Payload queries GCE metadata server for OAuth tokens |
| Discovery | Cloud Infrastructure Discovery | T1580 | Exfiltrated token used to enumerate BigQuery datasets, GKE clusters, Cloud Logging |
| Lateral Movement | Use Alternate Authentication Material: Application Access Token | T1550.001 | Stolen P4SA token with cloud-platform scope enables cross-service access |
| Collection | Data from Cloud Storage | T1530 | Cross-deployment model theft from other GCS-stored models |
| Exfiltration | Exfiltration Over Web Service | T1567 | Credentials exfiltrated to attacker-controlled webhook |
| Defense Evasion | Obfuscated Files or Information | T1027 | Malicious code hidden within serialized pickle byte stream |

---

## Impact

- **Severity:** High (CVSS 7.7)
- **Scope:** Any Vertex AI user running SDK versions >= 1.21.0 and < 1.133.0 (per CVE database), or specifically tested on v1.139.0 and v1.140.0 (per Unit 42)
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
6. **Rotate service account credentials** if you suspect a staging bucket may have been squatted.
7. **Enable VPC Service Controls** around Vertex AI and Cloud Storage to restrict cross-project bucket access.

### Detection Opportunities

- Monitor GCS audit logs for object writes to buckets matching `*-vertex-staging-*` where the writer's project differs from the bucket name's project ID prefix.
- Alert on process creation events where a Python process performing model loading (joblib/pickle) spawns shell interpreters or network tools.
- Monitor metadata server access (`169.254.169.254` or `metadata.google.internal`) from Vertex AI prediction containers for token requests.
- Scan model artifacts (`.pkl`, `.joblib`) with picklescan or similar tools before deployment.

---

## Detection Rules

### Sigma Rules

**Rule 1: Suspicious Vertex AI Model Upload to Predictable GCS Staging Bucket**
Detects GCS object creation events targeting buckets matching the predictable Vertex AI staging naming convention, combined with model artifact file patterns. **Status: PASS** (sigma check exit 0, converted to Splunk and LogScale).

**Rule 2: Pickle Deserialization Leading to Code Execution in ML Model Serving Container**
Detects suspicious child process creation from Python processes involved in model loading or prediction serving. **Status: PASS** (sigma check exit 0, converted to Splunk and LogScale).

**Rule 3: GCE Metadata Server Access from Vertex AI Prediction Container**
Detects command-line evidence of processes reaching the GCE metadata endpoint for token retrieval, a key post-exploitation indicator. **Status: PASS** (sigma check exit 0, converted to Splunk and LogScale).

```yaml
title: Suspicious Vertex AI Model Upload to Predictable GCS Staging Bucket
id: 8a3f1c9e-7d2b-4e5a-b6c8-9f0a1d3e5b7c
status: experimental
description: >
  Detects GCS API calls uploading model artifacts to buckets matching the
  predictable Vertex AI staging bucket naming convention. Attackers exploit
  CVE-2026-2473 by pre-creating these buckets (bucket squatting) to intercept
  model uploads and inject malicious pickle payloads for cross-tenant RCE.
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
    data.resource.labels.bucket_name|re: '.*-vertex-staging-.*'
  selection_method:
    data.protoPayload.methodName:
      - 'storage.objects.create'
      - 'storage.objects.insert'
  selection_artifact:
    data.protoPayload.resourceName|contains:
      - 'model.joblib'
      - 'model.pkl'
      - 'saved_model.pb'
      - 'vertex_ai_auto_staging'
  condition: selection_bucket_pattern and selection_method and selection_artifact
falsepositives:
  - Legitimate Vertex AI model uploads using default SDK staging buckets owned by the same project
  - CI/CD pipelines using older SDK versions with predictable bucket naming
level: medium
```

```yaml
title: Pickle Deserialization Leading to Code Execution in ML Model Serving Container
id: 2b4d6e8f-1a3c-5d7e-9f0b-2c4d6a8e0f1a
status: experimental
description: >
  Detects process execution events originating from Python pickle or joblib
  deserialization within ML model serving containers, indicative of malicious
  model payloads exploiting CVE-2026-2473. Attackers craft pickle objects with
  __reduce__ methods that execute commands upon joblib.load().
references:
  - https://unit42.paloaltonetworks.com/hijacking-vertex-ai-model/
  - https://cvereports.com/reports/CVE-2026-2473
author: Actioner CTI
date: 2026-06-17
tags:
  - attack.t1059.006
  - attack.t1059.004
  - attack.t1027
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
      - 'predict'
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

```yaml
title: GCE Metadata Server Access from Vertex AI Prediction Container
id: 3c5e7f9a-2b4d-6e8f-0a1c-3d5f7b9e1a2c
status: experimental
description: >
  Detects HTTP requests to the GCE metadata server from within a Vertex AI
  prediction container. In CVE-2026-2473, malicious pickle payloads query the
  metadata endpoint to steal OAuth tokens with broad cloud-platform scope,
  enabling lateral movement to BigQuery, Cloud Logging, and other tenants.
references:
  - https://unit42.paloaltonetworks.com/hijacking-vertex-ai-model/
  - https://cvereports.com/reports/CVE-2026-2473
author: Actioner CTI
date: 2026-06-17
tags:
  - attack.t1552.005
  - attack.t1580
  - cve.2026-2473
logsource:
  category: process_creation
  product: linux
detection:
  selection_curl_metadata:
    Image|endswith:
      - '/curl'
      - '/wget'
      - '/python'
      - '/python3'
    CommandLine|contains:
      - 'metadata.google.internal'
      - '169.254.169.254'
  selection_token_path:
    CommandLine|contains:
      - '/computeMetadata/v1/instance/service-accounts'
      - 'access_token'
      - 'Metadata-Flavor'
  condition: selection_curl_metadata and selection_token_path
falsepositives:
  - Legitimate application code querying instance metadata for configuration
  - SDK initialization routines fetching default credentials
level: medium
```

### YARA Rules

**Rule 1: Malicious_Pickle_Reduce_Exec**
Detects pickle files containing protocol headers combined with REDUCE opcodes and dangerous module references (os.system, subprocess, builtins.exec). **Status: PASS** (yarac exit 0, warnings about short hex string are expected and non-blocking).

**Rule 2: Malicious_Joblib_Pickle_Payload**
Detects joblib-serialized files containing dangerous callables combined with GCE metadata theft indicators, targeting the specific post-exploitation pattern from CVE-2026-2473. **Status: PASS** (yarac exit 0).

**Rule 3: Pickle_GCE_Metadata_Token_Theft**
Detects pickle payloads crafted specifically to steal GCE metadata service OAuth tokens, matching the exact exfiltration technique described in the Unit 42 research. **Status: PASS** (yarac exit 0, warnings about short hex string are expected and non-blocking).

```yara
rule Malicious_Pickle_Reduce_Exec
{
    meta:
        description = "Detects Python pickle payloads using __reduce__ to invoke os.system, subprocess, or exec for code execution. Common in model poisoning attacks like CVE-2026-2473."
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
        $reduce_opcode = { 52 }
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
        $numpy_marker = { 93 4E 55 4D 50 59 }
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
        ($joblib_marker or $numpy_marker) and
        (any of ($os_system, $os_popen, $subprocess_call, $subprocess_popen,
                 $builtins_exec, $builtins_eval, $posix_system)) and
        (any of ($metadata_url, $compute_metadata, $service_accounts))
}

rule Pickle_GCE_Metadata_Token_Theft
{
    meta:
        description = "Detects pickle payloads specifically crafted to steal GCE metadata service OAuth tokens, a key post-exploitation step in the Vertex AI cross-tenant RCE attack chain."
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
        $reduce = { 52 }

    condition:
        (any of ($pickle_v*)) and
        $reduce and
        (any of ($metadata1, $metadata2)) and
        ($token_path or $header)
}
```

### Suricata Rules

**Rule 1: ETPRO EXPLOIT Vertex AI Staging Bucket Model Upload**
Detects HTTP POST requests to `storage.googleapis.com` with URI containing `vertex-staging` and model file extensions, indicating potential bucket squatting model upload interception. **Status: PASS** (suricata -T exit 0).

**Rule 2: ETPRO EXPLOIT GCE Metadata Token Access from Prediction Container**
Detects HTTP requests to the link-local metadata endpoint (169.254.169.254) requesting service account tokens with the GCE metadata header. **Status: PASS** (suricata -T exit 0).

**Rule 3: ETPRO EXPLOIT Suspected OAuth Token Exfiltration Post Pickle Deserialization**
Detects outbound HTTP POST requests with JSON bodies containing `access_token` and `cloud-platform`, indicating exfiltration of stolen GCE OAuth tokens. **Status: PASS** (suricata -T exit 0).

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO EXPLOIT Vertex AI Staging Bucket Model Upload - Possible Bucket Squatting (CVE-2026-2473)"; flow:established,to_server; http.method; content:"POST"; http.host; content:"storage.googleapis.com"; http.uri; content:"vertex-staging"; content:"upload"; pcre:"/\.(pkl|joblib|pickle|pb)(\?|$)/"; reference:url,unit42.paloaltonetworks.com/hijacking-vertex-ai-model/; reference:cve,2026-2473; classtype:attempted-admin; sid:1000001; rev:1;)

alert http $HOME_NET any -> 169.254.169.254 any (msg:"ETPRO EXPLOIT GCE Metadata Token Access from Prediction Container - Possible CVE-2026-2473 Post-Exploitation"; flow:established,to_server; http.uri; content:"/computeMetadata/v1/instance/service-accounts/"; http.header; content:"Metadata-Flavor"; content:"Google"; reference:url,unit42.paloaltonetworks.com/hijacking-vertex-ai-model/; reference:cve,2026-2473; classtype:credential-theft; sid:1000002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ETPRO EXPLOIT Suspected OAuth Token Exfiltration Post Pickle Deserialization (CVE-2026-2473)"; flow:established,to_server; http.method; content:"POST"; http.header; content:"Content-Type"; content:"application/json"; http.request_body; content:"access_token"; content:"cloud-platform"; reference:url,unit42.paloaltonetworks.com/hijacking-vertex-ai-model/; reference:cve,2026-2473; classtype:trojan-activity; sid:1000003; rev:1;)
```

---

## Sources

1. [Pickle in the Middle -- Hijacking Vertex AI Model Uploads for Cross-Tenant RCE (Unit 42)](https://unit42.paloaltonetworks.com/hijacking-vertex-ai-model/) -- Primary research by Ori Hadad, Palo Alto Networks Unit 42.
2. [CVE-2026-2473: Bucket Squatting on Google Vertex AI (CVEReports)](https://cvereports.com/reports/CVE-2026-2473) -- CVE entry with CVSS 7.7, CWE-340 classification.
3. [Google Vertex AI SDK Flaw Let Attackers Hijack Model Uploads via Bucket Squatting (The Hacker News)](https://thehackernews.com/2026/06/google-vertex-ai-sdk-flaw-let-attackers.html) -- Coverage including remediation guidance and timeline.
4. [Kicking the Bucket: Critical RCE and Cross-Tenant Exploits in 3 Different GCP Products (Focal Security)](https://focalsecurity.io/blog/kicking-the-bucket-gcp-cross-tenant/) -- Related GCP bucket squatting research providing broader context on the attack class.
5. [googleapis/python-aiplatform Releases (GitHub)](https://github.com/googleapis/python-aiplatform/releases) -- Official SDK release notes for patched versions.
