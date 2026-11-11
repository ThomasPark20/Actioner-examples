rule SupplyChain_Ethersphere_Evjawbreaker_Go_Backdoor
{
    meta:
        description = "Detects the evjawbreaker Go remote shell backdoor deployed via the compromised @ethersphere/bee-js and Swarm Desktop supply chain attack"
        author = "Actioner"
        date = "2026-11-11"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "9b73e7cd4e1425e770392549d8df46c706139ef476f4f7b9ac405165dc8d9696"
        hash = "b601776817363b96295119f7221338a122d5247a35a77a64b04f286e1bbcc565"
        hash = "80d2672e2599732d3c0ae2a4cd0d1e3fe4d555a60273ce33feb99db3f34d250f"
        hash = "fae61f31f00988fdc5cc9e7272b51e08af2e245d81003237875415930fd27358"
        severity = "critical"

    strings:
        $pkg1 = "evjawbreaker/internal/hubclient" ascii
        $pkg2 = "evjawbreaker" ascii
        $marker1 = "__JAWBRK_DONE__" ascii
        $marker2 = "__JAWBRK_EC__" ascii
        $contract = "0xf8a900Db50b3331be6B768bA460BB59f3E40C344" ascii nocase
        $selector = "02d91518" ascii
        $dep = "creack/pty" ascii

    condition:
        (uint32(0) == 0x464C457F or uint32(0) == 0xBEBAFECA or uint32(0) == 0xFEEDFACF or uint32(0) == 0xFEEDFACE) and
        filesize < 20MB and
        ($pkg1 or (2 of ($marker*, $pkg2, $dep)) or ($contract and $selector))
}

rule SupplyChain_Ethersphere_BeeJS_Malicious_Loader
{
    meta:
        description = "Detects the malicious loader script injected into @ethersphere/bee-js 13.3.0 generate-version.cjs"
        author = "Actioner"
        date = "2026-11-11"
        reference = "https://safedep.io/blog/ethersphere-bee-js-npm-compromise"
        hash = "ee2f762e9ed3fd89f106e0b80c2e923bf1aed9a280277d3d998a5902c4d9ec0f"
        severity = "critical"

    strings:
        $url = "api.frameworkmetrics.xyz" ascii
        $path1 = "/v1/analytics" ascii
        $path2 = "/v1/electron" ascii
        $header = "X-Ethersphere" ascii
        $exec = "new Function" ascii
        $args = "'require', 'console', 'process'" ascii

    condition:
        filesize < 100KB and
        $url and
        ($path1 or $path2) and
        $header and
        ($exec or $args)
}

rule SupplyChain_Ethersphere_InvokePS1_UAC_Bypass
{
    meta:
        description = "Detects the obfuscated invoke.ps1 PowerShell loader used for UAC bypass (UACME method 39) in the bee-js supply chain attack"
        author = "Actioner"
        date = "2026-11-11"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "37d14bff30762ca701e9c1f8bc6c57c065bb20ae3a2208cb7411a6530610f08e"
        severity = "high"

    strings:
        $s1 = "uac39" ascii nocase
        $s2 = "COR_PROFILER" ascii
        $s3 = "COR_ENABLE_PROFILING" ascii
        $s4 = "profiler.dll" ascii nocase
        $s5 = "UAC39_PAYLOAD" ascii
        $s6 = ".stuffed-" ascii
        $msi = "app.msi" ascii
        $sc = "ScreenConnect" ascii nocase

    condition:
        filesize < 1MB and
        3 of them
}
