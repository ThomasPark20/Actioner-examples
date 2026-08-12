rule LiteLLM_Malicious_PTH_Startup_Hook
{
    meta:
        description = "Detects the malicious litellm_init.pth file (34,628 bytes) used in litellm 1.82.8 supply chain attack. Matches triple base64 encoded payload structure and embedded RSA-4096 public key."
        author = "Actioner"
        date = "2026-08-12"
        reference = "https://safedep.io/malicious-litellm-1-82-8-analysis/"
        reference2 = "https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel"
        hash = "d2a0d5f564628773b6af7b9c11f6b86531a875bd2d186d7081ab62748a800ebb"
        severity = "critical"

    strings:
        $pth_marker = "litellm_init" ascii
        $b64_import = "import base64" ascii
        $b64_decode = "base64.b64decode" ascii
        $exec_call = "exec(" ascii
        $rsa_key_prefix = "MIICIjANBgkqhkiG9w0BAQEFAAOCAQ" ascii
        $persist_var = "PERSIST_B64" ascii
        $b64_script_var = "B64_SCRIPT" ascii
        $sysmon_path = ".config/sysmon/sysmon.py" ascii
        $sysmon_service = "sysmon.service" ascii
        $c2_domain = "models.litellm.cloud" ascii

    condition:
        filesize < 100KB and
        (
            ($c2_domain) or
            ($rsa_key_prefix and $exec_call and $b64_decode) or
            ($persist_var and $b64_script_var) or
            ($pth_marker and 2 of ($b64_import, $b64_decode, $exec_call, $sysmon_path, $sysmon_service))
        )
}

rule LiteLLM_Proxy_Server_Payload_Injection
{
    meta:
        description = "Detects malicious code injected into litellm/proxy/proxy_server.py in version 1.82.7. The payload contains base64-encoded credential harvester triggered on proxy import."
        author = "Actioner"
        date = "2026-08-12"
        reference = "https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/"
        severity = "critical"

    strings:
        $proxy_marker = "proxy_server" ascii
        $b64_decode = "base64.b64decode" ascii
        $exec_call = "exec(" ascii
        $c2_exfil = "models.litellm.cloud" ascii
        $c2_backdoor = "checkmarx.zone" ascii
        $archive_name = "tpcp.tar.gz" ascii
        $encrypt_aes = "aes-256-cbc" ascii nocase
        $session_key = "session.key" ascii
        $payload_enc = "payload.enc" ascii

    condition:
        filesize < 5MB and
        $c2_exfil and
        ($proxy_marker or $c2_backdoor) and
        (2 of ($b64_decode, $exec_call, $archive_name, $encrypt_aes, $session_key, $payload_enc))
}

rule LiteLLM_TeamPCP_Credential_Harvester
{
    meta:
        description = "Detects the credential harvesting payload from the LiteLLM supply chain attack. Requires TeamPCP-specific IOCs co-occurring with credential access patterns to avoid behavioral-only matches."
        author = "Actioner"
        date = "2026-08-12"
        reference = "https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html"
        severity = "high"

    strings:
        $teampcp_c2_1 = "models.litellm.cloud" ascii
        $teampcp_c2_2 = "checkmarx.zone" ascii
        $teampcp_archive = "tpcp.tar.gz" ascii
        $teampcp_header = "X-Filename: tpcp.tar.gz" ascii
        $teampcp_sysmon = ".config/sysmon/sysmon.py" ascii

        $cred_aws = ".aws/credentials" ascii
        $cred_kube = ".kube/config" ascii
        $cred_ssh = ".ssh/id_rsa" ascii
        $cred_gcp = "application_default_credentials.json" ascii
        $cred_env = ".env.production" ascii

        $imds = "169.254.169.254" ascii
        $k8s_secrets = "/api/v1/secrets" ascii

    condition:
        filesize < 1MB and
        any of ($teampcp_*) and
        (2 of ($cred_*) or $imds or $k8s_secrets)
}
