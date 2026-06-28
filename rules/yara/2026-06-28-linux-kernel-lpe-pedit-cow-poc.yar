rule Exploit_CVE_2026_46331_PeditCOW_POC
{
    meta:
        description = "Detects the pedit COW exploit PoC (packet_edit_meme) for CVE-2026-46331 targeting Linux kernel tc pedit page-cache corruption"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://github.com/sgkdev/packet_edit_meme"
        severity = "critical"

    strings:
        $s1 = "packet_edit_meme" ascii fullword
        $s2 = "pedit_primitive" ascii fullword
        $s3 = "/bin/su" ascii
        $s4 = "act_pedit" ascii
        $s5 = "--ubuntu" ascii
        $s6 = "aa-exec" ascii
        $s7 = "CAP_NET_ADMIN" ascii
        $s8 = "page cache" ascii nocase
        $s9 = "tcf_pedit_act" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        ($s1 or $s2) and
        2 of ($s3, $s4, $s5, $s6, $s7, $s8, $s9)
}
