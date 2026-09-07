import "pe"

rule Malware_SLEEPWALKER_Backdoor : sleepwalker backdoor
{
    meta:
        description = "Detects the SLEEPWALKER passive backdoor DLL that side-loads into ESET Management Agent (ERAAgent.exe) using static AES-256-CCM key, forged ESET version info, and dpapisvc.dll forwarding"
        author = "Actioner"
        date = "2026-08-27"
        reference = "https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/"
        hash = "d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Static AES-256-CCM key (32 bytes)
        $aes_key = { 74 65 31 ff 37 8d bb 4b b5 1d 2a a2 b1 d3 8d 90 53 50 a9 59 58 31 86 ba f4 c6 90 f5 f3 16 b3 ae }

        // Configuration nonce (12 bytes)
        $config_nonce = { 3a 6d 35 7f b9 bc 51 ea cc 8b 85 09 }

        // DLL forwarding target - non-existent Windows component
        $fwd_dll = "dpapisvc.dll" ascii wide

        // Exported function names matching dpapi.dll
        $exp1 = "CryptProtectDataNoUI" ascii
        $exp2 = "CryptUnprotectDataNoUI" ascii
        $exp3 = "CryptProtectMemory" ascii
        $exp4 = "CryptUnprotectMemory" ascii
        $exp5 = "CryptResetMachineCredentials" ascii
        $exp6 = "CryptUpdateProtectedState" ascii
        $exp7 = "iCryptIdentifyProtection" ascii

        // Runtime resolved API names
        $api1 = "VirtualProtect" ascii
        $api2 = "SetSecurityDescriptorDacl" ascii
        $api3 = "CryptGenRandom" ascii

        // Process name check
        $proc_check = "ERAAgent.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 100KB and
        (
            $aes_key or
            $config_nonce or
            (
                $fwd_dll and
                $proc_check and
                3 of ($exp*)
            ) or
            (
                $fwd_dll and
                2 of ($api*) and
                2 of ($exp*)
            )
        )
}
