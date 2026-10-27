rule SupplyChain_LiteLLM_Cook_PTH
{
    meta:
        description = "Detects the malicious cook.pth startup hook file from the compromised LiteLLM 1.107.0 release"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb"
        hash = "84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pth_import = "import cook" ascii

    condition:
        filesize < 100 and $pth_import
}

rule SupplyChain_LiteLLM_Cook_Py_Collector
{
    meta:
        description = "Detects the cook.py credential collector wrapper from the compromised LiteLLM 1.107.0 release, which base64-decodes and zlib-decompresses the PRIVCOLLECT stealer"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        hash = "03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $b64_decode = "base64.b64decode" ascii
        $zlib_decomp = "zlib.decompress" ascii
        $exec_call = "exec(" ascii
        $privcollect = "privcollect" ascii nocase
        $pc_once = ".pc_once_" ascii
        $aes_cbc = "aes-256-cbc" ascii nocase
        $healthcheck = "/healthcheck" ascii
        $x_token = "XWiA8gZNa7NcX2XRoAEb" ascii

    condition:
        filesize < 200KB and
        (
            (3 of ($b64_decode, $zlib_decomp, $exec_call, $privcollect)) or
            ($pc_once and $healthcheck) or
            ($x_token and 1 of ($b64_decode, $zlib_decomp, $exec_call)) or
            ($aes_cbc and $privcollect)
        )
}

rule SupplyChain_LiteLLM_Sitecustomize_Loader
{
    meta:
        description = "Detects the malicious sitecustomize.py remote code loader from the compromised LiteLLM 1.107.0 release"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        hash = "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa"
        hash = "b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $loader_lock = "remote_code_loader.lock" ascii
        $domain_txt = "domain.txt" ascii
        $codepy = "/codepy" ascii
        $letters9813 = "letters9813" ascii
        $pythonclient = "pythonclient-test" ascii
        $setsid = "os.setsid" ascii
        $devnull = "/dev/null" ascii
        $privcollect = "privcollect" ascii nocase
        $pc_once = ".pc_once_72129118c59f5636c0bb" ascii

    condition:
        filesize < 200KB and
        (
            ($loader_lock and ($domain_txt or $codepy)) or
            ($letters9813 and $pythonclient) or
            ($pc_once and $privcollect) or
            ($setsid and $devnull and $loader_lock)
        )
}
