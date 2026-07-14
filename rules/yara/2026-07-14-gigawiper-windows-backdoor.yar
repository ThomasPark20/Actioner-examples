rule Malware_GigaWiper_Backdoor_Strings
{
    meta:
        description = "Detects GigaWiper Golang backdoor via characteristic function names, package references, PDB paths, and operational strings"
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001"
        severity = "critical"

    strings:
        $fn1 = "rabbit_tools_tool_wipe_main" ascii
        $fn2 = "rabbit_tools_tool_ran_main_cmd_extort" ascii
        $fn3 = "rabbit_tools_tool_wipec_main" ascii
        $fn4 = "rabbit_bin.RunOnceRegistryMain" ascii
        $fn5 = "BigBangExtortMain" ascii
        $fn6 = "GRATClientInfo" ascii

        $pdb1 = "GRAT\\CWipeNew\\Release\\CWipeNew.pdb" ascii
        $pdb2 = "GRAT\\CWipe\\Release\\CWipe.pdb" ascii

        $str1 = "Partitions removed successfully" ascii
        $str2 = "Task created. Original process exiting." ascii
        $str3 = "Running from Task Scheduler" ascii
        $str4 = "Exec cmd wipe-file" ascii
        $str5 = "Exec cmd keylog" ascii
        $str6 = "Exec cmd wipe32" ascii
        $str7 = "kharbvnmhkjbkjb" ascii
        $str8 = ".candy" ascii

        $cfg1 = "OneDrive Update" ascii wide
        $cfg2 = "Microsoft.Windows.CloudExperienceHost" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            2 of ($fn*) or
            1 of ($pdb*) or
            (3 of ($str*) and 1 of ($cfg*)) or
            ($fn5 and $str8)
        )
}

import "hash"

rule Malware_GigaWiper_Hashes
{
    meta:
        description = "Detects known GigaWiper, Crucio, and FlockWiper samples by SHA-256 hash"
        author = "Actioner"
        date = "2026-07-14"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        severity = "critical"
        note = "The hash module computes a full-file SHA-256 for every scanned file, which adds CPU and I/O overhead. Consider deploying this rule only in targeted scans or alongside a pre-filter that limits the scan set."

    condition:
        hash.sha256(0, filesize) == "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001" or
        hash.sha256(0, filesize) == "ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913" or
        hash.sha256(0, filesize) == "f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd" or
        hash.sha256(0, filesize) == "9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683" or
        hash.sha256(0, filesize) == "3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd" or
        hash.sha256(0, filesize) == "440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3" or
        hash.sha256(0, filesize) == "12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721" or
        hash.sha256(0, filesize) == "db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674"
}
