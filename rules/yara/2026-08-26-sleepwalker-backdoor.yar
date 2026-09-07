rule sleepwalker_backdoor
{
    meta:
        description = "Detects SLEEPWALKER passive Windows backdoor - DLL side-loaded into ESET Management Agent as dpapi.dll with custom 23-instruction bytecode command language"
        author = "Actioner"
        date = "2026-08-26"
        reference = "https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/"
        hash = "d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60"
        hash_md5 = "2318327b29bb1c0e2d2b5f0211fc7fac"
        hash_sha1 = "2ec8aa9661a33bccc002150ce1ed02d90c3986ff"

    strings:
        // Embedded AES-256 key used for config/command decryption
        $aes_key = { 74 65 31 ff 37 8d bb 4b b5 1d 2a a2 b1 d3 8d 90 53 50 a9 59 58 31 86 ba f4 c6 90 f5 f3 16 b3 ae }

        // Config nonce for AES-256-CCM
        $config_nonce = { 3a 6d 35 7f b9 bc 51 ea cc 8b 85 09 }

        // Companion DLL name - not a legitimate Windows component
        $dpapisvc = "dpapisvc.dll" ascii wide

        // Forged version resource strings
        $eset_version = "ESET Management Agent Module" ascii wide
        $original_name = "dpapi.dll" ascii wide

        // Exported DPAPI forwarding function names (distinctive set)
        $export1 = "CryptProtectDataNoUI" ascii
        $export2 = "CryptUnprotectDataNoUI" ascii
        $export3 = "CryptProtectMemory" ascii
        $export4 = "CryptUnprotectMemory" ascii
        $export5 = "CryptResetMachineCredentials" ascii
        $export6 = "CryptUpdateProtectedState" ascii
        $export7 = "iCryptIdentifyProtection" ascii

        // Process name check target (ERAAgent.exe)
        $eraagent = "ERAAgent.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 100KB and
        (
            ($aes_key and $config_nonce) or
            ($dpapisvc and $eset_version and $original_name) or
            ($dpapisvc and $eraagent and 4 of ($export*))
        )
}
