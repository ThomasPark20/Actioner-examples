import "hash"

rule TSGA_Backdoor_CPconfigdaemon
{
    meta:
        description = "Detects TSGA backdoor binaries (CPconfigdaemon / slot_CPconfigdaemon) associated with PHP2Shell campaign on Check Point gateways"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        hash1 = "4171b521fa6441382aa2fa014a08e18ff9a6e0ab6096c9144072bf46b37a2ec8"
        hash2 = "d7549671c7189979f0624ec52dad9ea6a707d23146e3585ab8f8c4720eca0c63"
        audit_note = "s2 (CPconfigdaemon) is a substring of s1 (slot_CPconfigdaemon); a match on s1+s2 alone is effectively single-indicator confidence"

    strings:
        $s1 = "slot_CPconfigdaemon" ascii
        $s2 = "CPconfigdaemon" ascii
        $s3 = "/tmp/.p_sock" ascii
        $s4 = "/tmp/.bd.log" ascii

        $elf = { 7f 45 4c 46 }

    condition:
        $elf at 0 and (2 of ($s*))
}

rule Destroy_V6_Wiper
{
    meta:
        description = "Detects the destroy_v6 wiper binary used in the PHP2Shell campaign to wipe VMware ESXi hosts"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        hash = "c7d9477309fac6c638a1128442056a242de086996add8cb49cd6496c36003237"

    strings:
        $s1 = "DREAM_ANNEXATION" ascii
        $s2 = "destroy_v6" ascii

        $elf = { 7f 45 4c 46 }

    condition:
        $elf at 0 and (2 of ($s*))
}

rule PHP2Shell_Webshell_TPL
{
    meta:
        description = "Detects PHP webshells used in the PHP2Shell campaign targeting Check Point Mobile Access portals, matching the zz-prefix .tpl pattern with hardcoded key"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        hash = "edb3e92eb7bda7413a09edcc4b1ba3cbed4bcdf42808a8abce63b6e4c3fda2b3"

    strings:
        $key = "zz2026" ascii
        $func1 = "system(" ascii
        $func2 = "exec(" ascii
        $func3 = "eval(" ascii
        $func4 = "base64_decode" ascii
        $upload = "upload_progress_pwn" ascii
        $tpl = "challenge_render" ascii

    condition:
        filesize < 100KB and ($key or $upload or $tpl) and (1 of ($func*))
}

rule TSProxy_Shared_Library
{
    meta:
        description = "Detects the TSProxy shared library (libcpfwcommon.so) used by TSGA backdoor for network function hooking and encrypted proxying"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        hash = "fb1a6235eb6bce8c9ec8cd8bb85f17c9c2bde8ecb45b7a243a30ceadf26654da"

    strings:
        $elf = { 7f 45 4c 46 }
        $s1 = "libcpfwcommon" ascii
        $s2 = "/tmp/.p_sock" ascii
        $s3 = "libdssafe" ascii

    condition:
        $elf at 0 and (2 of ($s*))
}

rule PHP2Shell_Campaign_Known_Hashes
{
    meta:
        description = "Detects known malware samples from the PHP2Shell campaign by SHA-256 hash"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"

    condition:
        hash.sha256(0, filesize) == "4171b521fa6441382aa2fa014a08e18ff9a6e0ab6096c9144072bf46b37a2ec8" or
        hash.sha256(0, filesize) == "d7549671c7189979f0624ec52dad9ea6a707d23146e3585ab8f8c4720eca0c63" or
        hash.sha256(0, filesize) == "edb3e92eb7bda7413a09edcc4b1ba3cbed4bcdf42808a8abce63b6e4c3fda2b3" or
        hash.sha256(0, filesize) == "c7d9477309fac6c638a1128442056a242de086996add8cb49cd6496c36003237" or
        hash.sha256(0, filesize) == "3b51080a909023f7d484e2443740b572307ce0054eb9e32d98f0a06bfcd2db90" or
        hash.sha256(0, filesize) == "ee16e1695711b9d60c62925fcfb2fe1a29c18ae26565bc05410a14e16d2a39d7" or
        hash.sha256(0, filesize) == "fb1a6235eb6bce8c9ec8cd8bb85f17c9c2bde8ecb45b7a243a30ceadf26654da"
}
