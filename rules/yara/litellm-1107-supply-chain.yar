rule SupplyChain_LiteLLM_CookPy_Credential_Stealer
{
    meta:
        description = "Detects the malicious cook.py credential stealer from the LiteLLM 1.107.0 supply chain compromise"
        author = "Actioner"
        date = "2026-10-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        severity = "critical"

    strings:
        $s1 = "PRIVCOLLECT_ACTIVE" ascii
        $s2 = "remote_code_loader.lock" ascii
        $s3 = ".pc_once_72129118c59f5636c0bb" ascii
        $s4 = ".pc_e_" ascii
        $s5 = "/healthcheck" ascii
        $s6 = "X-SHA256" ascii
        $s7 = "LiteLLM_CredentialsTable" ascii
        $s8 = "LiteLLM_ProxyModelTable" ascii
        $s9 = "data.bin" ascii
        $s10 = "key.bin" ascii
        $s11 = "hdr.json" ascii

    condition:
        filesize < 1MB and 5 of them
}

rule SupplyChain_LiteLLM_PRIVCOLLECT_Strings
{
    meta:
        description = "Detects PRIVCOLLECT credential harvesting strings and staging patterns from the LiteLLM 1.107.0 supply chain compromise"
        author = "Actioner"
        date = "2026-10-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        severity = "critical"

    strings:
        $priv1 = "PRIVCOLLECT_ACTIVE" ascii
        $priv2 = ".pc_once_72129118c59f5636c0bb" ascii
        $priv3 = ".pc_e_" ascii
        $priv4 = ".pc_" ascii
        $staging1 = "/tmp/.pc_once_" ascii
        $staging2 = "/tmp/.pc_e_" ascii
        $exfil1 = "application/octet-stream" ascii
        $exfil2 = "X-SHA256" ascii
        $code_loader = "remote_code_loader" ascii

    condition:
        filesize < 1MB and
        (
            ($priv1 and 2 of ($priv*)) or
            (2 of ($staging*) and 1 of ($exfil*)) or
            ($code_loader and 2 of ($priv*))
        )
}

rule SupplyChain_LiteLLM_RSA_PublicKey_Fragment
{
    meta:
        description = "Detects embedded RSA public key fragments used for credential wrapping in the LiteLLM 1.107.0 supply chain compromise"
        author = "Actioner"
        date = "2026-10-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        severity = "medium"

    strings:
        $rsa_begin = "-----BEGIN PUBLIC KEY-----" ascii
        $rsa_end = "-----END PUBLIC KEY-----" ascii
        $priv1 = "PRIVCOLLECT_ACTIVE" ascii
        $priv2 = "remote_code_loader" ascii
        $priv3 = ".pc_e_" ascii

    condition:
        filesize < 1MB and
        $rsa_begin and $rsa_end and
        1 of ($priv*)
}
