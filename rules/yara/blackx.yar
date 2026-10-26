rule Bootkit_BlackX_Installer_Strings
{
    meta:
        description = "Detects BlackX UEFI bootkit components via installer-specific strings, RC4 key, encrypted container name, and RAT command identifiers"
        author = "Actioner"
        date = "2026-10-26"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Distinctive strings — any one of these is a strong BlackX indicator
        $installer_container = "PVMDIJGKAX2" ascii wide
        $rc4_key = "Q46F6MDLI3RX2KV1" ascii wide
        $rat_method = "TEST.Class1.RunCMD" ascii wide
        $c2_domain = "archivetj.com" ascii wide

        // Supporting strings — individually generic, meaningful only in combination
        $plugin_export = "create_plugin" ascii fullword
        $encrypted_payload = "v8_context_snapshot.bin" ascii wide
        $rat_suffix_sssr = "SSSR" ascii fullword
        $rat_suffix_01 = "0X01" ascii fullword
        $rat_suffix_02 = "0X02" ascii fullword

    condition:
        1 of ($installer_container, $rc4_key, $rat_method, $c2_domain) or
        4 of them
}

rule Bootkit_BlackX_OxiDLLRunner_Sideload
{
    meta:
        description = "Detects the legitimate jcef_helper.exe binary (renamed googleupdate.exe) abused by BlackX for DLL sideloading based on PE metadata"
        author = "Actioner"
        date = "2026-10-26"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        hash = "af8a983b9ada07eae1259bf2953abd40"
        severity = "high"
        tlp = "WHITE"

    strings:
        $original_name = "jcef_helper.exe" ascii wide
        $c2_domain = "archivetj.com" ascii wide
        $plugin_fn = "create_plugin" ascii fullword
        $container = "PVMDIJGKAX2" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $original_name and
        1 of ($c2_domain, $plugin_fn, $container)
}
