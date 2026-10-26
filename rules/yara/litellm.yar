rule SupplyChain_LiteLLM_CookPTH_Loader
{
    meta:
        description = "Detects the cook.pth loader file from the LiteLLM v1.107.0 supply chain compromise that triggers credential theft on Python startup"
        author = "Actioner"
        date = "2026-10-26"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb"
        severity = "critical"

    strings:
        $pth_import = "import cook" ascii fullword

    condition:
        filesize < 1KB and $pth_import
}

rule SupplyChain_LiteLLM_PRIVCOLLECT_Stealer
{
    meta:
        description = "Detects the PRIVCOLLECT credential stealer payload from the LiteLLM v1.107.0 supply chain compromise. Matches decoded/decompressed content or sitecustomize.py; on-disk cook.py uses Base64+zlib and requires decoding or memory scan."
        author = "Actioner"
        date = "2026-10-26"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        severity = "critical"

    strings:
        $s1 = "PRIVCOLLECT_ACTIVE" ascii
        $s2 = "remote_code_loader.lock" ascii
        $s3 = "/healthcheck" ascii
        $s4 = "litellm.dev" ascii
        $s5 = "letters9813" ascii
        $s6 = "pythonclient-test" ascii
        $s7 = ".pc_once_72129118c59f5636c0bb" ascii
        $s8 = "LiteLLM_CredentialsTable" ascii
        $s9 = "LiteLLM_ProxyModelTable" ascii

    condition:
        filesize < 5MB and 4 of them
}
