rule Destroy_V6_Wiper
{
    meta:
        description = "Detects the destroy_v6 Linux ELF wiper used in the PHP2Shell Check Point campaign for ESXi wiping"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html"
        severity = "critical"

    strings:
        $s1 = "DREAM_ANNEXATION" ascii
        $s2 = "destroy_v6" ascii

    condition:
        uint32(0) == 0x464C457F and
        all of ($s*)
}
