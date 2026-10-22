rule SupplyChain_LiteLLM_CookPth : litellm supply_chain
{
    meta:
        description = "Detects the malicious cook.pth file used in the LiteLLM v1.107.0 supply chain attack for Python startup persistence"
        author = "Actioner"
        date = "2026-10-22"
        reference = "https://www.aikido.dev/blog/litellm-compromised-infostealer-rat"
        severity = "critical"
        hash = "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb"
        hash = "84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d"

    strings:
        $pth_content = "import cook" fullword

    condition:
        filesize < 50 and $pth_content
}

rule SupplyChain_LiteLLM_CookPy_Stealer : litellm supply_chain stealer
{
    meta:
        description = "Detects the decoded privcollect credential stealer payload from the LiteLLM v1.107.0 supply chain attack. Strings target the decompressed/decoded stealer module (~61KB), not the obfuscated cook.py wrapper."
        author = "Actioner"
        date = "2026-10-22"
        reference = "https://stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer"
        severity = "critical"

    strings:
        $s1 = "privcollect" ascii
        $s2 = "PRIVCOLLECT_ACTIVE" ascii
        $s3 = "PC_URL" ascii
        $s4 = "PC_TOKEN" ascii
        $s5 = "PC_PUBKEY" ascii
        $s6 = "PC_MODULES" ascii
        $s7 = "PC_ONCE_PATH" ascii
        $s8 = ".pc_once_72129118c59f5636c0bb" ascii
        $s9 = "pc_post" ascii
        $s10 = "p14c7d1bb" ascii
        $rsa_prefix = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvxRBQMVXDXVskKS47haU" ascii
        $x_token = "XWiA8gZNa7NcX2XRoAEb" ascii
        $exfil_url = "litellm.dev/healthcheck" ascii
        $ua = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)" ascii

    condition:
        filesize < 100KB and (3 of ($s*) or $rsa_prefix or ($x_token and $exfil_url) or ($ua and $exfil_url))
}

rule SupplyChain_LiteLLM_CookPy_Obfuscated : litellm supply_chain stealer
{
    meta:
        description = "Detects the obfuscated cook.py wrapper file from the LiteLLM v1.107.0 supply chain attack. This is the on-disk form that uses Base64 + zlib compression as a single-line payload."
        author = "Actioner"
        date = "2026-10-22"
        reference = "https://stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer"
        severity = "critical"
        hash = "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        hash = "03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea"

    strings:
        $decode_pattern = "exec(compile(zlib.decompress(base64.b64decode(" ascii
        $import_pattern = "import base64,zlib" ascii
        $alt_import = "import zlib,base64" ascii
        $alt_import2 = "import base64, zlib" ascii

    condition:
        filesize > 10KB and filesize < 50KB and $decode_pattern and ($import_pattern or $alt_import or $alt_import2)
}

rule SupplyChain_LiteLLM_Sitecustomize_RAT : litellm supply_chain rat
{
    meta:
        description = "Detects the malicious sitecustomize.py RAT module from the LiteLLM v1.107.0 supply chain attack that fetches and executes remote Python code"
        author = "Actioner"
        date = "2026-10-22"
        reference = "https://www.wiz.io/blog/litellm-compromised-steals-credentials"
        severity = "critical"
        hash = "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa"
        hash = "b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465"

    strings:
        $s1 = "remote_code_loader" ascii
        $s2 = "exec_code" ascii
        $s3 = "/codepy" ascii
        $s4 = "LOOP_INTERVAL" ascii
        $s5 = "GITHUB_RAW_URL" ascii
        $s6 = "resolve_domain" ascii
        $s7 = "fetch_text" ascii
        $s8 = "letters9813" ascii
        $s9 = "pythonclient-test" ascii
        $exec_pattern = "exec(compile(code" ascii

    condition:
        filesize < 100KB and (3 of ($s*) or ($exec_pattern and 1 of ($s*)))
}

rule SupplyChain_LiteLLM_Wheel_1107 : litellm supply_chain
{
    meta:
        description = "Detects LiteLLM v1.107.0 malicious wheel files by embedded payload indicators in the compressed archive"
        author = "Actioner"
        date = "2026-10-22"
        reference = "https://stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer"
        severity = "critical"

    strings:
        $wheel_meta = "litellm-1.107.0" ascii
        $pth_entry = "cook.pth" ascii
        $cook_entry = "cook.py" ascii
        $maturin = "tool.maturin" ascii
        $data_cook = "data = \"cook\"" ascii

    condition:
        filesize < 50MB and $wheel_meta and ($pth_entry or $cook_entry) and ($maturin or $data_cook)
}
