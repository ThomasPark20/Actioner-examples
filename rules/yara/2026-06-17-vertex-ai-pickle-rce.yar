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
        description = "Detects joblib-serialized files containing dangerous callables combined with GCE metadata theft indicators, targeting model poisoning in ML pipelines such as the Vertex AI bucket squatting attack (CVE-2026-2473). Most CVE-specific rule in this set."
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
