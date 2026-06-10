rule Exploit_RoguePlanet_Defender_LPE
{
    meta:
        description = "Detects the RoguePlanet exploit tool targeting Microsoft Defender TOCTOU race condition for SYSTEM privilege escalation"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://github.com/MSNightmare/RoguePlanet"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $api1 = "NtSetInformationFile" ascii fullword
        $api2 = "NtDeleteFile" ascii fullword
        $api3 = "NtOpenDirectoryObject" ascii fullword
        $api4 = "NtQueryDirectoryObject" ascii fullword
        $api5 = "NtQueryInformationFile" ascii fullword

        $lib1 = "virtdisk.dll" ascii nocase
        $lib2 = "bcrypt.dll" ascii nocase
        $lib3 = "ntdll.dll" ascii nocase

        $str1 = "IHATEMICROSOFT" ascii wide
        $str2 = "RoguePlanet" ascii wide
        $str3 = "mpasbase.vdm" ascii wide nocase
        $str4 = "mpavbase.vdm" ascii wide nocase
        $str5 = "$PWNed666!!!WDFAIL" ascii wide
        $str6 = "Nightmare" ascii wide
        $str7 = "MSRC" ascii wide

        $path1 = "Windows Defender\\Definition Updates" ascii wide nocase
        $path2 = "ProgramData\\Microsoft\\Windows Defender" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (3 of ($api*) and 1 of ($lib*) and 1 of ($str*)) or
            (2 of ($str1, $str2, $str5)) or
            ($str2 and 2 of ($api*) and 1 of ($path*))
        )
}
