rule Malware_NuGet_CryptoWalletAnalyzer
{
    meta:
        description = "Detects the trojanized Crypto Wallet Analyzer application from the malicious NuGet campaign. Loads a disguised native DLL (vcruntime146_cor2.dll) and polls GitHub for C2 commands."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "e7e7649f7249cb32f3123299e3a200c83dc210420b40f944168c36ab781b9458"
        severity = "high"

    strings:
        $dll_name = "vcruntime146_cor2.dll" ascii wide
        $export = "dropper_dll.dll" ascii
        $export2 = "JSON_OBJECT" ascii
        $pdb = "crypto_wallet_analyzer" ascii wide nocase
        $pdb2 = "CryptoWalletAnalyzer.pdb" ascii wide
        $aes_key = "HKJzuefjkhsadhfaosdhfkja" ascii
        $github = "Best-Seller-Dev" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            ($dll_name and ($export or $export2)) or
            ($pdb and $dll_name) or
            ($aes_key) or
            ($github and $dll_name) or
            ($pdb2 and 1 of ($export, $export2, $dll_name))
        )
}
