rule Malware_GigaWiper_Backdoor_Strings
{
    meta:
        description = "Detects GigaWiper Go-based destructive backdoor via characteristic function names, command strings, and GRAT framework references"
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001"
        hash = "ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913"
        severity = "critical"

    strings:
        // Go package/function names unique to GigaWiper
        $func1 = "rabbit_tools_tool_wipe_main" ascii
        $func2 = "rabbit_tools_tool_ran_main_cmd_extort" ascii
        $func3 = "rabbit_tools_tool_wipec_main" ascii
        $func4 = "RunOnceRegistryMain" ascii
        $func5 = "GRATClientInfo" ascii
        $func6 = "BigBangExtortMain" ascii

        // C2 configuration strings
        $c2_1 = "185.182.193.21" ascii
        $c2_2 = "212.8.248.104" ascii
        $amqp = "amqp://" ascii

        // Exchange names used in RabbitMQ C2
        $exch1 = "\"All\"" ascii
        $exch2 = "\"Topic\"" ascii

        // Distinctive operational strings
        $op1 = "Running from Task Scheduler" ascii
        $op2 = "kharbvnmhkjbkjb" ascii
        $op3 = "OneDrive Update" ascii wide
        $op4 = ".candy" ascii
        $op5 = "image_danger.jpg" ascii

        // Registry path
        $reg = "SOFTWARE\\OneDrive\\Environment" ascii wide

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        filesize < 30MB and
        (
            3 of ($func*) or
            (2 of ($c2*) and 1 of ($func*)) or
            ($op2 and 1 of ($func*)) or
            (2 of ($op*) and $reg) or
            ($amqp and $exch1 and $exch2 and 1 of ($func*))
        )
}

rule Malware_GigaWiper_Standalone_Wiper
{
    meta:
        description = "Detects GigaWiper standalone wiper component via disk wiping function references and multi-pass overwrite patterns"
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd"
        severity = "critical"

    strings:
        $wipe1 = "FindWindowsDrive" ascii
        $wipe2 = "unallocateDrive" ascii
        $wipe3 = "writeRandToDrive" ascii
        $wipe4 = "WipeMain" ascii
        $wipe5 = "WipeCMain" ascii

        // Multi-pass status messages from FlockWiper reimplementation
        $pass = "Pass 1 Time took:" ascii
        $grat = "GRAT" ascii

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        filesize < 30MB and
        (
            3 of ($wipe*) or
            (2 of ($wipe*) and $pass) or
            ($wipe1 and $wipe2 and $wipe3 and $grat)
        )
}

rule Malware_FlockWiper_PDB_Path
{
    meta:
        description = "Detects FlockWiper C-based wiper samples via PDB paths containing the GRAT project framework identifier"
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721"
        hash = "db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674"
        severity = "critical"

    strings:
        $pdb1 = "A:\\GRAT\\CWipeNew\\Release\\CWipeNew.pdb" ascii
        $pdb2 = "E:\\files\\new\\GRAT\\CWipe\\Release\\CWipe.pdb" ascii
        $pdb3 = "\\GRAT\\CWipe" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        any of ($pdb*)
}

rule Malware_Crucio_Ransomware_Strings
{
    meta:
        description = "Detects Crucio ransomware samples sharing code with GigaWiper Command 3 (fake ransomware / BigBangExtortMain)"
        author = "Actioner"
        date = "2026-07-11"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3"
        severity = "high"

    strings:
        $s1 = "BigBangExtortMain" ascii
        $s2 = ".candy" ascii
        $s3 = "image_danger.jpg" ascii
        $s4 = "key.txt" ascii

        // Command-line arguments
        $arg1 = "-k" ascii
        $arg2 = "-i" ascii
        $arg3 = "--keyfile" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            ($s1 and $s2) or
            ($s2 and $s3 and 2 of ($arg*)) or
            ($s1 and $s3 and $s4)
        )
}
