rule Exploit_CVE_2026_43503_DirtyClone_POC
{
    meta:
        description = "Detects the DirtyClone exploit PoC for CVE-2026-43503 targeting Linux kernel skb clone page-cache corruption via IPsec"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/"
        severity = "critical"

    strings:
        $s1 = "DirtyClone" ascii nocase
        $s2 = "dirtyclone" ascii
        $s3 = "SKBFL_SHARED_FRAG" ascii
        $s4 = "__pskb_copy_fclone" ascii
        $s5 = "vmsplice" ascii
        $s6 = "ip xfrm" ascii
        $s7 = "/usr/bin/su" ascii
        $s8 = "page cache" ascii nocase
        $s9 = "esp_input" ascii
        $s10 = "cbc(aes)" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        ($s1 or $s2) and
        2 of ($s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10)
}
