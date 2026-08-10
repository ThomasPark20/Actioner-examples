rule Malware_GigaWiper_Go_Backdoor
{
    meta:
        description = "Detects GigaWiper Go-based destructive backdoor via distinctive function names and strings"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001"
        hash = "ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913"
        hash = "f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd"
        hash = "9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683"
        severity = "critical"

    strings:
        $fn1 = "rabbit_tools_tool_wipe_main.WipeMain" ascii
        $fn2 = "rabbit_tools_tool_ran_main_cmd_extort.RanMain" ascii
        $fn3 = "rabbit_tools_tool_ran_main_bin.BigBangExtortMain" ascii
        $fn4 = "rabbit_tools_tool_wipec_main.WipeCMain" ascii
        $fn5 = "rabbit_bin.RunOnceRegistryMain" ascii
        $fn6 = "GRATClientInfo" ascii
        $fn7 = "RTYPE_map_string_cmd_appInfoStc" ascii

        $str1 = "Partitions removed successfully" ascii
        $str2 = "kharbvnmhkjbkjb" ascii
        $str3 = "Key/IV required. Use -k/-i or" ascii
        $str4 = "Pass 1 Time took: %s" ascii
        $str5 = "Running from Task Scheduler" ascii
        $str6 = "Task created. Original process exiting." ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (3 of ($fn*) or (2 of ($fn*) and 2 of ($str*)) or 4 of ($str*))
}

rule Malware_FlockWiper_PDB
{
    meta:
        description = "Detects FlockWiper wiper component via PDB debug paths containing GRAT identifier"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721"
        hash = "db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674"
        severity = "critical"

    strings:
        $pdb1 = "A:\\GRAT\\CWipeNew\\Release\\CWipeNew.pdb" ascii
        $pdb2 = "E:\\files\\new\\GRAT\\CWipe\\Release\\CWipe.pdb" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        any of ($pdb*)
}
