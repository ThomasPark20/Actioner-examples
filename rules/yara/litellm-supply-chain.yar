rule Supply_Chain_LiteLLM_PRIVCOLLECT_Stealer
{
    meta:
        description = "Detects the PRIVCOLLECT credential stealer from the LiteLLM 1.107.0 supply chain compromise"
        author = "Actioner"
        date = "2026-10-25"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        severity = "critical"

    strings:
        $env = "PRIVCOLLECT_ACTIVE" ascii
        $marker = ".pc_once_72129118c59f5636c0bb" ascii
        $staging = ".pc_e_" ascii
        $exfil = "litellm.dev/healthcheck" ascii
        $loader_lock = "remote_code_loader.lock" ascii
        $dead_drop = "letters9813/pythonclient-test" ascii
        $codepy = "/codepy" ascii
        $table1 = "LiteLLM_CredentialsTable" ascii
        $table2 = "LiteLLM_ProxyModelTable" ascii
        $xsha = "X-SHA256" ascii

    condition:
        filesize < 5MB and 3 of them
}

rule Supply_Chain_LiteLLM_Cook_PTH
{
    meta:
        description = "Detects the malicious cook.pth Python startup hook from LiteLLM 1.107.0"
        author = "Actioner"
        date = "2026-10-25"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash1 = "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb"
        hash2 = "84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d"
        severity = "critical"

    strings:
        $hook = "import cook" ascii fullword

    condition:
        filesize < 1KB and $hook
}
