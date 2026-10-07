import "hash"

rule Malware_ClingSTUN_Backdoor_Strings : backdoor iot
{
    meta:
        description = "Detects ClingSTUN Linux proxy backdoor via characteristic strings found in malware samples across ARM, MIPS, PowerPC, and x86 architectures"
        author = "Actioner"
        date = "2026-10-07"
        reference = "https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure"
        hash = "dc892f5013edb0aa1e61e808511387373d8d120348b5be0929621d21e6e9946a"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $path1 = "/root/.cling" ascii
        $path2 = "/usr/local/bin/.cling" ascii
        $persist1 = "/etc/inittab" ascii
        $persist2 = "/etc/init.d/rcS" ascii
        $persist3 = "/etc/rc.d/rc.boot" ascii
        $wdog1 = "/dev/watchdog" ascii
        $wdog2 = "/dev/misc/watchdog" ascii
        $stun_magic = { 21 12 A4 42 }
        $tag1 = "realtek.selfrep" ascii
        $port = "33957" ascii
        $proc1 = "/proc/1/" ascii
        $proc2 = "/proc/mounts" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            (2 of ($path*)) or
            ($tag1 and $stun_magic) or
            (1 of ($path*) and 1 of ($persist*) and 1 of ($wdog*)) or
            ($tag1 and 2 of ($persist*)) or
            ($port and 1 of ($path*) and $stun_magic) or
            (1 of ($proc*) and 1 of ($path*) and 1 of ($wdog*))
        )
}

rule Malware_ClingSTUN_Backdoor_Hashes : backdoor iot
{
    meta:
        description = "Detects known ClingSTUN malware samples by SHA256 hash via YARA import"
        author = "Actioner"
        date = "2026-10-07"
        reference = "https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $elf = { 7F 45 4C 46 }

    condition:
        $elf at 0 and filesize < 5MB and
        (
            hash.sha256(0, filesize) == "dc892f5013edb0aa1e61e808511387373d8d120348b5be0929621d21e6e9946a" or
            hash.sha256(0, filesize) == "a297eddfa7abea8d411afc0f150f8f6f30e470a77204de87e3b0815fa9bb8a84" or
            hash.sha256(0, filesize) == "4fbd61cb9181ebbc4fe9a6e59d3c346dc00001da48d66bd890556fc6fad22b07" or
            hash.sha256(0, filesize) == "121f2050e3c891b29565fd73451fff7ae60199c86eb8d79ec1eb1d9844578487" or
            hash.sha256(0, filesize) == "48f9b72ce72ab7087794650d6eef10135345088384fbde1482f1c74a02b80302" or
            hash.sha256(0, filesize) == "e6e113783356446aef66e5296db45b244f318292af7cebc2a9bd76f095a95c4c" or
            hash.sha256(0, filesize) == "c1d8e2829ea63b9dc1cf2c3421a5093406adad4d6622e238376e78e908e0e6e8" or
            hash.sha256(0, filesize) == "48962b3893f2c8261e32e6b95ea7d463d145a529a8b2a6c987dd979454405c73" or
            hash.sha256(0, filesize) == "76692a23abe718b93e63edefd743971ec627c0cdf3778f856bd5ec88003deaa2" or
            hash.sha256(0, filesize) == "ec199c78c11040fd3127887222fd75a85e5797bf96aa691a117fdd83dd663d81" or
            hash.sha256(0, filesize) == "c0d8ffebfba969b1c1ca76bd9623bb623e9f95155c8ceca77d8fcc521435a497" or
            hash.sha256(0, filesize) == "f49f45303cbfccee14ff193ac9608f860e6d616f08c0ecbef1ec44f7c863d7ec" or
            hash.sha256(0, filesize) == "9391c6ad17aced1142607c0c623b18d86a7697cc483d204ffac94093e26b8068" or
            hash.sha256(0, filesize) == "e4d12208789f36efc5a1ff765088fed95d6bb5972d1a804a4536fd42366797d4" or
            hash.sha256(0, filesize) == "284e5ec8748f99fd1b8c331b699a5fe5fd4448bbaae0347a940f427f931c4d14" or
            hash.sha256(0, filesize) == "6581bf37184bb2db899b9893064d39dd314ea691adf3281cc0aa7e0a31e5138a" or
            hash.sha256(0, filesize) == "10d83c1748895361e07320f68d44d427b43cadd2cbffe0ab5e607ab03aec83da" or
            hash.sha256(0, filesize) == "2ed54e0f988a62039abed88f6394eb1e3d5ed931f0183556055417fb08844ecf" or
            hash.sha256(0, filesize) == "b90640b392827b4f2d280f6cf67860862953331917d42df23e1653a92f2f98ad" or
            hash.sha256(0, filesize) == "dfba6008a2c828a9cb62342aec53006ae05a60cb8d4c41c3fa216fd727e8c6a3" or
            hash.sha256(0, filesize) == "5c4e263546fb21f8fe8732789a5b6583eaa8ae11ebeef099462a7c9bf50e022d"
        )
}
