import "hash"

rule Lazarus_Troy_Backdoor
{
    meta:
        description = "Detects Troy backdoor DLL deployed by Lazarus Group via SecurityPDF trojanized viewer"
        author = "Actioner"
        date = "2026-08-12"
        reference = "https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/"
        severity = "critical"
        tlp = "WHITE"
        hash1 = "590fb6ae19480d694e08ee85859cad8066f2f87e7e5abba2960c6d115e1615d6"
        hash2 = "68d4fba7b1300a59cd6212c08910a260cd71b40cd9f51cac933030a68faac0bb"
        hash3 = "a738059ce07c951c31ab2da3d93d8f69bff32f9b7d933dbf5943441b9cc99075"

    strings:
        $cmd_wait = "WAIT" ascii fullword
        $cmd_drives = "DRIVES" ascii fullword
        $cmd_list = "LIST" ascii fullword
        $cmd_open = "OPEN" ascii fullword
        $cmd_delete = "DELETE" ascii fullword
        $cmd_zipdownload = "ZIPDOWNLOAD" ascii fullword
        $cmd_download = "DOWNLOAD" ascii fullword
        $cmd_upload = "UPLOAD" ascii fullword
        $cmd_cmd = "CMD" ascii fullword
        $cmd_mem = "mem" ascii fullword
        $cmd_pk = "pk" ascii fullword
        $cmd_pvd = "pvd" ascii fullword
        $cmd_pv = "pv" ascii fullword
        $cmd_defaultsleep = "DEFAULTSLEEP" ascii fullword
        $cmd_getconfig = "GET_CONFIG" ascii fullword
        $cmd_setconfig = "SET_CONFIG" ascii fullword

        $c2_1 = "envell.xyz" ascii wide
        $c2_2 = "enveil.online" ascii wide
        $c2_3 = "uxtramine.org" ascii wide

        $troy_marker = "This document is encrypted with sumatrapdf reader" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            hash.sha256(0, filesize) == "590fb6ae19480d694e08ee85859cad8066f2f87e7e5abba2960c6d115e1615d6" or
            hash.sha256(0, filesize) == "68d4fba7b1300a59cd6212c08910a260cd71b40cd9f51cac933030a68faac0bb" or
            hash.sha256(0, filesize) == "a738059ce07c951c31ab2da3d93d8f69bff32f9b7d933dbf5943441b9cc99075" or
            (6 of ($cmd_*) and 1 of ($c2_*)) or
            (12 of ($cmd_*) and $troy_marker)
        )
}
