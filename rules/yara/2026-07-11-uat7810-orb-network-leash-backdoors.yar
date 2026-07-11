rule UAT7810_LONGLEASH_backdoor
{
    meta:
        description = "Detects LONGLEASH backdoor (aka ff-agent/nz1.0) used by UAT-7810 for ORB network C2 relay. Targets MIPS/ARM/x64 ELF binaries with distinctive internal project names and User-Agent string."
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f"

    strings:
        $project_name1 = "ff-agent" ascii
        $project_name2 = "nz1.0" ascii
        $user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36" ascii
        $lib_boost = "boost" ascii
        $lib_nanopb = "nanopb" ascii
        $lib_mbedtls = "mbedtls" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            ($project_name1 and $project_name2) or
            ($user_agent and any of ($project_name*)) or
            ($user_agent and 2 of ($lib_*))
        )
}

rule UAT7810_DOGLEASH_passive_backdoor
{
    meta:
        description = "Detects DOGLEASH passive backdoor used by UAT-7810. Listens on hardcoded port, accepts TCP commands decoded with hardcoded password. Identified by command handler dispatch codes."
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f"

    strings:
        // Command dispatch codes (little-endian 16-bit values in context)
        $cmd_exec1 = { 68 22 }  // 0x2268
        $cmd_exec2 = { 67 22 }  // 0x2267
        $cmd_read  = { 66 22 }  // 0x2266
        $cmd_rename = { 71 22 } // 0x2271
        $cmd_close1 = { 73 22 } // 0x2273
        $cmd_close2 = { 74 22 } // 0x2274
        $cmd_osinfo = { 50 34 } // 0x3450

        $shell_exec = "/bin/sh" ascii
        $shell_flag = "-c" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        $shell_exec and $shell_flag and
        4 of ($cmd_*)
}

rule UAT7810_JARLEASH_java_backdoor
{
    meta:
        description = "Detects JARLEASH Java-based backdoor used by UAT-7810 for web-based file management, FTP/SFTP servers, and netcat deployment on compromised routers."
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "324d95024fc8da5c92b5a1f4825aed5a2a91c9ca8fb6aa52abb332a4c9cf4257"

    strings:
        $jar_magic = { 50 4B 03 04 }  // ZIP/JAR magic
        $class_ext = ".class" ascii
        $manifest = "META-INF/MANIFEST.MF" ascii

        // Network and file management capabilities
        $cap_ftp = "FtpServer" ascii
        $cap_sftp = "SftpServer" ascii
        $cap_netcat = "netcat" ascii nocase
        $cap_filemanager = "FileManager" ascii

        // Chinese language comments observed in config
        $chinese1 = { E4 B8 AD } // UTF-8 for common Chinese character
        $chinese2 = { E6 96 87 } // UTF-8 for another common Chinese character

    condition:
        $jar_magic at 0 and
        $manifest and
        $class_ext and
        (
            (2 of ($cap_*)) or
            (1 of ($cap_*) and 1 of ($chinese*))
        )
}

rule UAT7810_LEASHTEST_dev_binary
{
    meta:
        description = "Detects LEASHTEST development/testing binary (internal name iot-test) used by UAT-7810 for testing MIPS platform functionality before deploying operational implants."
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        hash = "1b5649b479fd625de5c8120873644b5eb669cc89cd504582c18e0ae350fd8823"

    strings:
        $internal_name = "iot-test" ascii
        $project1 = "ff-agent" ascii
        $project2 = "nz1.0" ascii
        $test_thread = "thread" ascii
        $test_tcp = "tcp" ascii
        $test_bind = "bind" ascii
        $test_async = "async" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        $internal_name and
        (1 of ($project*)) and
        3 of ($test_*)
}
