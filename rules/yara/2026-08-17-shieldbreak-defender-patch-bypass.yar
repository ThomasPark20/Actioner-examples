rule Exploit_ShieldBreak_Defender_LPE
{
    meta:
        description = "Detects the ShieldBreak exploit tool (CVE-2026-69414) that bypasses the RoguePlanet patch to achieve SYSTEM privilege escalation via Defender DLL sideloading through phoneinfo.dll"
        author = "Actioner"
        date = "2026-08-17"
        reference = "https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $name1 = "ShieldBreak" ascii wide
        $name2 = "Nightmare" ascii wide
        $name3 = "NightmareEclipse" ascii wide
        $name4 = "projectnightcrawler" ascii wide

        $dll1 = "phoneinfo.dll" ascii wide nocase
        $dll2 = "wer.dll" ascii wide nocase
        $dll3 = "wermgr.exe" ascii wide nocase

        $api1 = "NtSetInformationFile" ascii fullword
        $api2 = "NtDeleteFile" ascii fullword
        $api3 = "NtOpenDirectoryObject" ascii fullword
        $api4 = "CfRegisterSyncRoot" ascii fullword
        $api5 = "CfConnectSyncRoot" ascii fullword

        $clfs1 = "clfsw32.dll" ascii wide nocase
        $clfs2 = "CreateLogFile" ascii fullword
        $clfs3 = "AddLogContainer" ascii fullword

        $task1 = "QueueReporting" ascii wide
        $eicar1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" ascii

        $path1 = "\\system32\\phoneinfo.dll" ascii wide nocase
        $path2 = "Windows Defender" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($name1 and 2 of ($dll*, $api*, $clfs*, $task1, $path*)) or
            ($dll1 and $path1 and 1 of ($api*)) or
            ($dll1 and $task1 and 1 of ($clfs*)) or
            (2 of ($name*) and 1 of ($dll*) and 1 of ($api*)) or
            ($eicar1 and $dll1 and 1 of ($api*))
        )
}
