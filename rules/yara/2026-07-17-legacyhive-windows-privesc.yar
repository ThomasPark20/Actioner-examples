rule Exploit_LegacyHive_ProfSvc_PoC
{
    meta:
        description = "Detects the LegacyHive PoC exploit binary targeting Windows User Profile Service for privilege escalation via registry hive redirection"
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://www.cyderes.com/howler-cell/legacyhive-windows-user-profile-loading-vulnerability"
        severity = "critical"

    strings:
        $poc1 = "oplock triggered" wide ascii
        $poc2 = "Hive loaded" wide ascii
        $poc3 = "press any key to unload and exit" wide ascii

        $path1 = "globalroot\\BaseNamedObjects\\Restricted" wide ascii
        $path2 = "BaseNamedObjects\\Restricted\\Microsoft" wide ascii

        $reg1 = "User Shell Folders" wide ascii
        $reg2 = "Local AppData" wide ascii

        $api1 = "NtCreateSymbolicLinkObject" ascii
        $api2 = "NtCreateDirectoryObjectEx" ascii
        $api3 = "OROpenHiveByHandle" ascii
        $api4 = "RegOpenUserClassesRoot" ascii
        $api5 = "ORSetValue" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($poc*) and 1 of ($path*)) or
            (2 of ($path*) and 2 of ($api*)) or
            (1 of ($poc*) and 2 of ($api*) and 1 of ($reg*))
        )
}
