rule ROMULUS_Stardock_Malicious_DLL
{
    meta:
        description = "Detects the malicious I++u.dll or patched DeElevator64.dll used in the ROMULUS Route A Stardock DeElevation DLL sideloading chain"
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://www.forescout.com/?p=115732"
        hash1 = "0457414c4504b70115798eee9c8384a8bf9e793461ffb2e0661a6dcc6ed4809f"
        hash2 = "3cd1484cc5bf10e22d79784beba58a75d7b126c46efb5e1a85d6aab884447621"
        severity = "high"

    strings:
        // Strings that may also appear in legitimate Stardock software
        $s1 = "DeElevate64" ascii wide
        $s4 = "Build.dat" ascii wide
        $s6 = "Stardock Smart DeElevation Tool" ascii wide

        // Malware-specific strings not found in legitimate Stardock binaries
        $s2 = "I++u" ascii wide
        $s3 = "senddmp.resources" ascii wide
        $s5 = "execute_engine_disconnect.raw" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (1 of ($s2, $s3, $s5)) and
        3 of them
}
