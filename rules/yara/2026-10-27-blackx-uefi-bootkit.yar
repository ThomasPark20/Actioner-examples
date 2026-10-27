rule APT41_BlackX_Bootkit_Installer
{
    meta:
        description = "Detects BlackX UEFI bootkit installer and associated components based on unique strings from the campaign targeting Central Asian diplomats"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $inst_arg = "PVMDIJGKAX2" ascii wide
        $rc4_key = "Q46F6MDLI3RX2KV1" ascii wide
        $path1 = "\\ProgramData\\Intel\\inst.exe" ascii wide
        $payload_file = "v8_context_snapshot.bin" ascii wide
        $plugin_export = "create_plugin" ascii fullword
        $dotnet_method = "TEST.Class1.RunCMD" ascii
        $tag_sssr = "SSSR" ascii fullword
        $pdb_xdd = "\\xdd\\Desktop\\" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($inst_arg and $rc4_key) or
            ($dotnet_method and $tag_sssr) or
            ($plugin_export and $payload_file) or
            (3 of them)
        )
}

rule APT41_BlackX_OxiDLLRunner
{
    meta:
        description = "Detects the OxiDLLRunner component of the BlackX UEFI bootkit campaign, an OLLVM-obfuscated DLL that decrypts and launches a Rust payload"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $export = "create_plugin" ascii fullword
        $payload = "v8_context_snapshot.bin" ascii wide
        $c2 = "archivetj.com" ascii wide
        $xdd = "xdd" ascii fullword
        $rust_marker = ".rustc" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        $c2 and
        (1 of ($export, $payload, $xdd, $rust_marker))
}

rule APT41_BlackX_RAT_CloudC2
{
    meta:
        description = "Detects the BlackX RAT component that uses cloud storage services (Google Drive, OneDrive, Yandex.Disk) for C2 communication"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "high"
        tlp = "WHITE"

    strings:
        $dotnet_method = "TEST.Class1.RunCMD" ascii
        $tag = "SSSR" ascii fullword
        $suffix1 = "0X01" ascii
        $suffix2 = "0X02" ascii
        $suffix3 = "0X03" ascii
        $suffix4 = "0X04" ascii
        $suffix5 = "0X05" ascii
        $suffix6 = "0X06" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $dotnet_method and
        ($tag or 3 of ($suffix*))
}
