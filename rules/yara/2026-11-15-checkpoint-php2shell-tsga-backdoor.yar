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

rule PHP2Shell_Webshell_CheckPoint
{
    meta:
        description = "Detects PHP webshells deployed via PHP2Shell exploitation on Check Point Mobile Access portals"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://securityaffairs.com/202982/hacking/unpatched-check-point-gateways-are-being-wiped-exploiting-php2shell.html"
        severity = "high"

    strings:
        $upload_marker = "upload_progress_pwn" ascii
        $tpl_staging = "/tmp/.up.tpl" ascii
        $challenge = "challenge_render.tpl" ascii
        $php_exec1 = "system(" ascii
        $php_exec2 = "passthru(" ascii
        $php_exec3 = "shell_exec(" ascii
        $php_upload = "move_uploaded_file(" ascii

    condition:
        ($upload_marker or $tpl_staging or $challenge) and
        any of ($php_exec*, $php_upload)
}
