rule ROMULUS_LegionLoader_Stage3
{
    meta:
        description = "Detects LegionLoader Stage 3 PE payload delivered via the ROMULUS ClickFix platform Route B chain, identified by its C2 endpoint patterns, Chrome credential theft strings, and custom protocol field IDs"
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://www.forescout.com/?p=115732"
        hash = "2e3d378d6a842af2404dfcd1dcbfc0df84b01b799b2c8270ddbfe5eb18837762"
        severity = "critical"

    strings:
        $c2_path1 = "/nfront.php" ascii
        $c2_path2 = "/nback.php" ascii
        $chrome1 = "os_crypt" ascii
        $chrome2 = "encrypted_key" ascii
        $chrome3 = "Chrome" ascii wide
        $chrome4 = "Local State" ascii wide
        $field_id1 = { 4D F1 4E 44 }
        $field_id2 = { AC 1A 81 23 }
        $field_id3 = { 0E C5 76 69 }
        $ua = "Chrome/131" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        (
            (all of ($c2_path*) and 2 of ($chrome*)) or
            (2 of ($field_id*) and 1 of ($c2_path*)) or
            (all of ($c2_path*) and $ua)
        )
}
