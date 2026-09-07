import "pe"

rule Malware_SLEEPWALKER_Backdoor
{
    meta:
        description = "Detects the SLEEPWALKER passive backdoor DLL via embedded AES key, config nonce, magic packet validation logic, and DPAPI masquerade exports."
        author = "Actioner (adapted from Dominik Reichel)"
        date = "2026-08-28"
        reference = "https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/"
        hash = "d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Static AES-256 key for task envelope decryption
        $aes_key = { 74 65 31 FF 37 8D BB 4B B5 1D 2A A2 B1 D3 8D 90
                      53 50 A9 59 58 31 86 BA F4 C6 90 F5 F3 16 B3 AE }

        // 12-byte nonce for bootstrap config envelope
        $config_nonce = { 3A 6D 35 7F B9 BC 51 EA CC 8B 85 09 }

        // Trigger-packet validation: XOR with 0xAAAA, compare against 0x1C minimum
        $magic_packet_algo = {
            49 83 FC 30
            0F 82 ?? ?? ?? ??
            47 0F B7 44 25 FC
            47 0F B7 4C 25 FE
            B8 AA AA 00 00
            41 0F B7 C8
            66 41 33 C9
            66 33 C8
            66 83 F9 1C
        }

        // Non-existent forwarding DLL
        $dpapi_svc = "dpapisvc.dll" wide

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        (
            any of ($aes_key, $config_nonce, $magic_packet_algo)
            or (
                pe.version_info["OriginalFilename"] contains "dpapi.dll" and
                (
                    pe.version_info["FileDescription"] contains "ESET Management Agent Module" or
                    $dpapi_svc
                ) and
                pe.exports("CryptProtectDataNoUI") and
                pe.exports("CryptProtectMemory") and
                pe.exports("CryptResetMachineCredentials") and
                pe.exports("CryptUnprotectDataNoUI") and
                pe.exports("CryptUnprotectMemory") and
                pe.exports("CryptUpdateProtectedState") and
                pe.exports("iCryptIdentifyProtection")
            )
        )
}
