rule SignDrop_CLFS_Exploit
{
    meta:
        description = "Detects the SignDrop CLFS privilege escalation exploit binary based on distinctive strings from the PoC"
        author = "Actioner"
        date = "2026-11-13"
        reference = "https://github.com/MSNightmare/SignDrop"
        threat = "Windows CLFS Local Privilege Escalation Zero-Day"

    strings:
        $api1 = "AddLogContainer" ascii wide
        $api2 = "ServerMpUpdateEngineSignature" ascii wide
        $clfs1 = ".cnpf" ascii wide
        $clfs2 = ".blf" ascii wide
        $clfs3 = "\\CLFS" ascii wide
        $proj1 = "SigDrop" ascii wide nocase
        $proj2 = "SignDrop" ascii wide nocase
        $idl1 = "windefend" ascii wide nocase
        $flag1 = "OBJ_FORCE_ACCESS_CHECK" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (($proj1 or $proj2) and $api2) or
            ($api1 and $api2 and ($clfs1 or $clfs2)) or
            ($api2 and $idl1 and ($clfs1 or $clfs2 or $clfs3)) or
            ($flag1 and $api2 and ($clfs1 or $clfs2))
        )
}

rule SignDrop_HID_Sideload_DLL
{
    meta:
        description = "Detects a suspicious hid.dll that may be used for DLL sideloading as part of the SignDrop exploit chain"
        author = "Actioner"
        date = "2026-11-13"
        reference = "https://github.com/MSNightmare/SignDrop"
        threat = "SignDrop DLL Sideloading Component"

    strings:
        $clfs1 = "AddLogContainer" ascii wide
        $clfs2 = ".cnpf" ascii wide
        $clfs3 = ".blf" ascii wide
        $defender1 = "ServerMpUpdateEngineSignature" ascii wide
        $defender2 = "windefend" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        2 of ($clfs1, $clfs2, $clfs3) and
        1 of ($defender1, $defender2)
}
