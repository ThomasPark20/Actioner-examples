/*
    HardBreacher -- Kaspersky Endpoint Security Zero-Day Privilege Escalation
    Source: https://github.com/MSNightmare/HardBreacher
    Report: summaries/2026-09-01-kaspersky-hardbreacher-zero-day.md
    Generated: 2026-09-01 | Version: 0.2 (REVISED)
    Rules: 2 YARA
*/

rule HardBreacher_Exploit_Binary
{
    meta:
        description = "Detects HardBreacher PoC exploit binary or SolidSnake DLL payload targeting Kaspersky Endpoint Security"
        author = "Actioner"
        date = "2026-09-01"
        reference = "https://github.com/MSNightmare/HardBreacher"
        reference = "https://securityaffairs.com/198214/hacking/chaotic-eclipse-releases-kaspersky-zero-day-hardbreacher.html"

    strings:
        $s1 = "MY_SNAKE_IS_SOLID.dll" ascii wide
        $s2 = "HardBreacher-SolidSnake-Sync-Event" ascii wide
        $s3 = "MySnakeIsSolid" ascii wide
        $s4 = "SolidSnake" ascii wide
        $s5 = "avpui.exe" ascii wide
        $s6 = "Notification from Kaspersky Endpoint Security" ascii wide

        $reg1 = "SOFTWARE\\WOW6432Node\\KasperskyLab\\protected\\KES" ascii wide
        $reg2 = "Kaspersky Lab\\KES.14.0.0" ascii wide

        $path1 = "\\Desktop\\Kaspy" ascii wide
        $path2 = "_avpui.dll" ascii wide

        $api1 = "NtCreateSymbolicLinkObject" ascii
        $api2 = "NtCreateDirectoryObject" ascii
        $api3 = "NtCreateUserProcess" ascii
        $api4 = "DefineDosDevice" ascii
        $api5 = "FSCTL_SET_REPARSE_POINT" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($s1 and $s2) or
            ($s2 and $s3) or
            ($s1 and any of ($api*)) or
            (3 of ($s*) and any of ($reg*)) or
            ($s6 and $s5 and any of ($api*)) or
            (any of ($path*) and $s2 and any of ($reg*))
        )
}

rule SolidSnake_DLL_Payload
{
    meta:
        description = "Detects SolidSnake DLL component of HardBreacher exploit - suppresses Kaspersky UI notifications and terminates avpui.exe"
        author = "Actioner"
        date = "2026-09-01"
        reference = "https://github.com/MSNightmare/HardBreacher/tree/main/SolidSnake"

    strings:
        $export = "MySnakeIsSolid" ascii
        $event = "HardBreacher-SolidSnake-Sync-Event" ascii wide
        $target = "avpui.exe" ascii wide
        $window = "Notification from Kaspersky Endpoint Security" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $export and
        any of ($event, $target, $window)
}
