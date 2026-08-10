import "hash"

rule Malware_GigaWiper_Backdoor_Strings
{
    meta:
        description = "Detects GigaWiper Golang backdoor via characteristic strings found in binary samples"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001"
        hash = "ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913"
        severity = "critical"

    strings:
        $s1 = "kharbvnmhkjbkjb" ascii
        $s2 = "Partitions removed successfully" ascii
        $s3 = "Running from Task Scheduler" ascii
        $s4 = "Task created. Original process exiting" ascii
        $s5 = "purge_cmd_queue" ascii
        $s6 = "purge_queue" ascii
        $s7 = "BigBangExtortMain" ascii
        $s8 = "WipeCMain" ascii
        $s9 = "WipeMain" ascii
        $s10 = "image_danger.jpg" ascii
        $s11 = ".candy" ascii

        $c2_1 = "185.182.193.21" ascii
        $c2_2 = "212.8.248.104" ascii

        $grat1 = "RTYPE_map_string_cmd_appInfoStc" ascii
        $grat2 = "GRAT" ascii

        $go1 = "go.buildid" ascii

    condition:
        filesize < 30MB and
        $go1 and
        (
            (4 of ($s*)) or
            (2 of ($s*) and 1 of ($c2_*)) or
            (1 of ($grat*) and 2 of ($s*))
        )
}

rule Malware_GigaWiper_Hashes
{
    meta:
        description = "Detects known GigaWiper, Crucio, and FlockWiper samples by SHA-256 hash"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        severity = "critical"

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

rule Malware_FlockWiper_PDB_Path
{
    meta:
        description = "Detects FlockWiper samples via characteristic PDB paths referencing the GRAT framework"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721"
        severity = "high"

    strings:
        $pdb1 = "A:\\GRAT\\CWipeNew\\Release\\CWipeNew.pdb" ascii
        $pdb2 = "E:\\files\\new\\GRAT\\CWipe\\Release\\CWipe.pdb" ascii

    condition:
        uint16(0) == 0x5A4D and
        any of ($pdb*)
}

rule Malware_GigaWiper_Wiper_Behavioral
{
    meta:
        description = "Detects GigaWiper wiper component via combination of disk wiping strings and Golang markers"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        severity = "high"

    strings:
        $wipe1 = "Partitions removed successfully" ascii
        $wipe2 = "Pass 1 Time took:" ascii
        $wipe3 = "Pass 2 Time took:" ascii
        $wipe4 = "Pass 3 Time took:" ascii
        $wipe5 = "WipeMain" ascii
        $wipe6 = "WipeCMain" ascii

        $disk1 = "IOCTL_DISK_CREATE_DISK" ascii wide
        $disk2 = "PHYSICALDRIVE" ascii wide
        $disk3 = "DeviceIoControl" ascii wide

        $go1 = "go.buildid" ascii

    condition:
        filesize < 30MB and
        $go1 and
        (2 of ($wipe*) or (1 of ($wipe*) and 1 of ($disk*)))
}
