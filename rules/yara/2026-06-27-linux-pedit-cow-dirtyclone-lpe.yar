rule packet_edit_meme_exploit_CVE_2026_46331
{
    meta:
        description = "Detects the packet_edit_meme PoC exploit binary for CVE-2026-46331 (pedit COW page-cache corruption LPE)"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://github.com/sgkdev/packet_edit_meme"
        severity = "critical"
        cve = "CVE-2026-46331"

    strings:
        $s1 = "packet_edit_meme" ascii
        $s2 = "pedit_primitive" ascii
        $s3 = "tcf_pedit_act" ascii
        $s4 = "act_pedit" ascii
        $s5 = "skb_ensure_writable" ascii

        $exploit_str1 = "/bin/su" ascii
        $exploit_str2 = "/bin/sh" ascii
        $exploit_str3 = "setgid" ascii
        $exploit_str4 = "setuid" ascii
        $exploit_str5 = "execve" ascii

        $cmd1 = "cls_basic" ascii
        $cmd2 = "em_meta" ascii
        $cmd3 = "matchall" ascii

        $ubuntu_bypass = "aa-exec" ascii
        $profile1 = "trinity" ascii
        $profile2 = "flatpak" ascii

        $cow_str1 = "page-cache" ascii nocase
        $cow_str2 = "page_cache" ascii nocase
        $cow_str3 = "cow" ascii nocase

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        (
            ($s1 and any of ($exploit_str*)) or
            ($s2 and $s4) or
            (3 of ($s*) and 2 of ($exploit_str*)) or
            ($s1 and $ubuntu_bypass) or
            (2 of ($cmd*) and any of ($exploit_str*)) or
            (any of ($cow_str*) and any of ($s*) and any of ($exploit_str*)) or
            ($ubuntu_bypass and any of ($profile*) and $s1)
        )
}

rule dirtyclone_exploit_CVE_2026_43503
{
    meta:
        description = "Detects DirtyClone exploit binaries or scripts for CVE-2026-43503 (page-cache corruption via IPsec packet cloning)"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/"
        severity = "critical"
        cve = "CVE-2026-43503"

    strings:
        $name1 = "DirtyClone" ascii nocase
        $name2 = "dirtyclone" ascii nocase
        $name3 = "dirty_clone" ascii nocase
        $name4 = "CVE-2026-43503" ascii

        $func1 = "__pskb_copy_fclone" ascii
        $func2 = "skb_shift" ascii
        $func3 = "nf_dup_ipv4" ascii
        $func4 = "esp_input" ascii
        $func5 = "SKBFL_SHARED_FRAG" ascii

        $exploit_cmd1 = "unshare -Urn" ascii
        $exploit_cmd2 = "xfrm state add" ascii
        $exploit_cmd3 = "xfrm policy add" ascii
        $exploit_cmd4 = "vmsplice" ascii
        $exploit_cmd5 = "splice" ascii
        $exploit_cmd6 = "-j TEE --gateway" ascii

        $target1 = "/usr/bin/su" ascii
        $target2 = "/bin/su" ascii

    condition:
        filesize < 5MB and
        (
            (any of ($name*) and 2 of ($exploit_cmd*)) or
            (2 of ($func*) and any of ($target*)) or
            ($exploit_cmd1 and $exploit_cmd2 and $exploit_cmd3 and $exploit_cmd6) or
            (any of ($name*) and any of ($func*) and any of ($target*))
        )
}

rule pagecache_poisoning_shellcode_generic
{
    meta:
        description = "Detects generic page-cache poisoning shellcode pattern: setgid(0)+setuid(0)+execve(/bin/sh) commonly injected into cached setuid binaries"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://thehackernews.com/2026/06/new-linux-pedit-cow-exploit-enables.html"
        severity = "high"

    strings:
        // x86_64 shellcode: setgid(0) - syscall 106
        $sc_setgid = { 48 31 FF 48 C7 C0 6A 00 00 00 0F 05 }

        // x86_64 shellcode: setuid(0) - syscall 105
        $sc_setuid = { 48 31 FF 48 C7 C0 69 00 00 00 0F 05 }

        // x86_64 shellcode: execve("/bin/sh") common pattern
        $sc_execve_binsh = { 2F 62 69 6E 2F 73 68 00 }

        // Common exploit strings
        $str_pagecache = "page.cache" ascii nocase
        $str_sendfile = "sendfile" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        (
            ($sc_setgid and $sc_setuid and $sc_execve_binsh) or
            (all of ($sc_*) and any of ($str_*))
        )
}

rule dirtyclone_python_poc
{
    meta:
        description = "Detects the Python-based DirtyClone PoC exploit script (CVE-2026-43503)"
        author = "Actioner CTI"
        date = "2026-06-27"
        reference = "https://github.com/aexdyhaxor/CVE-2026-43503-DirtyClone"
        severity = "critical"
        cve = "CVE-2026-43503"

    strings:
        $name1 = "dirtyclone" ascii nocase
        $name2 = "CVE-2026-43503" ascii
        $name3 = "DirtyClone" ascii

        $py_import1 = "import ctypes" ascii
        $py_import2 = "import os" ascii
        $py_import3 = "import subprocess" ascii

        $py_cmd1 = "unshare" ascii
        $py_cmd2 = "xfrm" ascii
        $py_cmd3 = "iptables" ascii
        $py_cmd4 = "/usr/bin/su" ascii
        $py_cmd5 = "/bin/su" ascii

    condition:
        filesize < 1MB and
        any of ($name*) and
        any of ($py_import*) and
        2 of ($py_cmd*)
}
