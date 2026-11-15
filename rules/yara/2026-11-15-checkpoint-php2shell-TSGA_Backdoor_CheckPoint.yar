rule TSGA_Backdoor_CheckPoint
{
    meta:
        description = "Detects TSGA backdoor deployed on Check Point gateways during PHP2Shell exploitation campaign"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html"
        severity = "high"

    strings:
        $s1 = "slot_CPconfigdaemon" ascii
        $s2 = "/tmp/.p_sock" ascii
        $s3 = "CPconfigdaemon" ascii
        $s4 = "libcpfwcommon.so" ascii
        $s5 = "libdssafe.so" ascii

    condition:
        uint32(0) == 0x464C457F and
        2 of ($s*)
}
