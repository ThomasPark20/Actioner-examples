rule Exploit_NCentral_4EverAble2Shell_PrivEsc
{
    meta:
        description = "Detects the 4EverAble2Shell privilege escalation Python script that abuses N-central helper functions to escalate from nable to root"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers"
        hash = "fc4c01fd11bc301cf312830460cfdccc3af9dcfe50c910b86d6a1117bc76c747"
        severity = "critical"

    strings:
        $s1 = "setLDFileOwner" ascii
        $s2 = "ServerChild.sh" ascii
        $s3 = "serverControl" ascii
        $s4 = "flag_default.json" ascii
        $s5 = "write_before" ascii
        $s6 = "write_after" ascii
        $s7 = "helper_restored" ascii
        $s8 = "nable_wrapper" ascii

    condition:
        filesize < 1MB and
        4 of them
}
