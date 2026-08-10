rule Malware_GigaWiper_BLUERABBIT_Strings
{
    meta:
        description = "Detects GigaWiper (BLUERABBIT) backdoor via distinctive Go function names and GRAT framework strings"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        severity = "critical"

    strings:
        $func1 = "rabbit_tools_tool_wipe_main" ascii
        $func2 = "rabbit_tools_tool_ran_main" ascii
        $func3 = "rabbit_tools_tool_wipec_main" ascii
        $func4 = "rabbit_bin.RunOnceRegistryMain" ascii
        $grat1 = "GRAT" ascii fullword
        $str1 = "Partitions removed successfully" ascii
        $str2 = "kharbvnmhkjbkjb" ascii
        $str3 = "Running from Task Scheduler" ascii
        $str4 = "Task created. Original process exiting." ascii
        $str5 = "purge_cmd_queue" ascii
        $str6 = "Exec cmd wipe-file" ascii
        $str7 = "Exec cmd keylog" ascii
        $str8 = "Exec cmd wipe32" ascii
        $pdb1 = "GRAT\\CWipeNew\\Release\\CWipeNew.pdb" ascii
        $pdb2 = "GRAT\\CWipe\\Release\\CWipe.pdb" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            2 of ($func*) or
            (1 of ($func*) and 2 of ($str*)) or
            any of ($pdb*) or
            ($grat1 and 3 of ($str*))
        )
}

rule Malware_GigaWiper_Crucio_Candy_Ransomware
{
    meta:
        description = "Detects GigaWiper Crucio-derived ransomware module with .candy file encryption"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        severity = "high"

    strings:
        $candy = ".candy" ascii
        $bigbang = "BigBangExtort" ascii
        $ranmain = "ran_main" ascii
        $keyreq = "Key/IV required" ascii
        $keyfile = "keyfile" ascii
        $wipe = "wipe_main" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        $candy and
        (
            $bigbang or
            ($ranmain and 1 of ($keyreq, $keyfile)) or
            ($wipe and 2 of ($keyreq, $keyfile, $ranmain))
        )
}
