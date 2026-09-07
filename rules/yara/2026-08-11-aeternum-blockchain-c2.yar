/*
    Actioner - Aeternum Blockchain C2 Detection Rules (YARA)
    Reference: https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/
    Date: 2026-08-11
*/

rule Malware_Aeternum_Loader_Strings
{
    meta:
        description = "Detects Aeternum botnet loader via distinctive strings including blockchain RPC function selector, User-Agent, and multipart boundary"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/"
        hash = "5bfb25b8255b61e5ffdf6804451534bcfa9f1dfd225e6c8cdcefb5f50d846898"
        severity = "high"

    strings:
        $func_selector = "0xb68d1809" ascii wide
        $ua1 = "SystemInfo Bot/2.0" ascii wide
        $ua2 = "cpp-httplib/0.18.3" ascii wide
        $boundary = "systeminfoboundary" ascii wide
        $persist1 = "Wmi_Framework_APIKEY_wmsnet" ascii wide
        $persist2 = "wmiframework.exe" ascii wide nocase
        $rpc1 = "eth_call" ascii wide
        $rpc2 = "polygon.rpc.hypersync.xyz" ascii wide
        $rpc3 = "polygon-mumbai.g.alchemy.com" ascii wide
        $contract1 = "0x04E25a563f159308FC3E15fE9Ccc9D2CF623D0cc" ascii
        $contract2 = "0x16dA95799CB8aB203f83e01AFC030B1217198Da4" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($func_selector and 1 of ($rpc*)) or
            ($ua1 and $boundary) or
            (2 of ($persist*)) or
            (1 of ($contract*) and $func_selector) or
            (3 of them)
        )
}

rule Malware_Aeternum_Python_Variant
{
    meta:
        description = "Detects Aeternum Python-based variant via distinctive XOR keys, C2 domains, and function patterns"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/"
        hash = "ea1b6ff3a0c1a749b9f09d66789973321d63d8896b48f7345193bdad512950a2"
        severity = "high"

    strings:
        $xor1 = "helo1" ascii
        $xor2 = "$m7*rYpry3" ascii
        $c2_1 = "sftp-api-group-wechat.com" ascii
        $c2_2 = "constant-path.xyz" ascii
        $c2_3 = "update-launcher.xyz" ascii
        $c2_4 = "test-steve.cyou" ascii
        $c2_5 = "cdnjsdelivr.beer" ascii
        $func1 = "get_domain" ascii
        $func2 = "send_tg" ascii
        $contract = "0xb0874252a7359AA701F3F144A1f03A6e0DA8aE6D" ascii
        $persist = "PythonLauncher-" ascii

    condition:
        filesize < 5MB and
        (
            (2 of ($c2_*)) or
            ($xor2 and 1 of ($func*)) or
            ($contract and 1 of ($func*)) or
            (3 of them)
        )
}
