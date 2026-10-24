rule SupplyChain_LiteLLM_1107_Payload : supply_chain credential_stealer
{
    meta:
        description = "Detects malicious files from the LiteLLM 1.107.0 supply chain compromise - cook.pth, cook.py, and sitecustomize.py payload files"
        author = "Actioner"
        date = "2026-10-24"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb"
        hash = "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        hash = "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pth_content = "import cook" ascii

        $privcollect_tag = "privcollect" ascii nocase
        $privcollect_active = "PRIVCOLLECT_ACTIVE" ascii
        $pc_url = "PC_URL" ascii
        $pc_token = "PC_TOKEN" ascii
        $pc_pubkey = "PC_PUBKEY" ascii
        $pc_modules = "PC_MODULES" ascii
        $pc_once = "PC_ONCE_PATH" ascii

        $exfil_domain = "www.litellm.dev" ascii
        $exfil_path = "/healthcheck" ascii
        $exfil_token = "XWiA8gZNa7NcX2XRoAEb" ascii

        $dead_drop = "letters9813/pythonclient-test" ascii
        $code_path = "/codepy" ascii
        $remote_loader = "remote_code_loader.lock" ascii

        $marker = ".pc_once_72129118c59f5636c0bb" ascii

        $obf_exec = "exec(zlib.decompress(base64.b64decode(" ascii
        $obf_namespace = "__name__': 'p14c7d1bb" ascii

        $db_table1 = "LiteLLM_CredentialsTable" ascii
        $db_table2 = "LiteLLM_ProxyModelTable" ascii

        $rsa_key_prefix = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvxRBQMVXDXVskKS47haU" ascii

    condition:
        filesize < 5MB and
        (
            ($pth_content and filesize < 100) or
            (3 of ($privcollect_tag, $privcollect_active, $pc_url, $pc_token, $pc_pubkey, $pc_modules, $pc_once)) or
            ($exfil_domain and ($exfil_token or $exfil_path)) or
            ($dead_drop and ($code_path or $remote_loader)) or
            ($marker) or
            ($obf_exec and $obf_namespace) or
            ($db_table1 and $db_table2 and $exfil_domain) or
            ($rsa_key_prefix) or
            ($remote_loader and $code_path)
        )
}

rule SupplyChain_LiteLLM_1107_Wheel : supply_chain
{
    meta:
        description = "Detects malicious LiteLLM 1.107.0 wheel packages containing the backdoor payload files in the data/purelib directory"
        author = "Actioner"
        date = "2026-10-24"
        reference = "https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $wheel_path = "litellm-1.107.0.data/purelib/" ascii
        $cook_pth = "cook.pth" ascii
        $cook_py = "cook.py" ascii
        $sitecustomize = "sitecustomize.py" ascii
        $maturin_data = "data = \"cook\"" ascii

    condition:
        filesize < 50MB and
        $wheel_path and
        2 of ($cook_pth, $cook_py, $sitecustomize, $maturin_data)
}
