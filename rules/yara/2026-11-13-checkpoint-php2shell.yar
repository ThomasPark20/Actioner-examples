rule TSGA_Backdoor_CPconfigdaemon
{
    meta:
        description = "Detects the TSGA backdoor (PhiliKit variant) deployed on Check Point gateways, masquerading as CPconfigdaemon"
        author = "Actioner"
        date = "2026-11-13"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        hash1 = "4171b521fa6441382aa2fa014a08e18ff9a6e0ab6096c9144072bf46b37a2ec8"
        hash2 = "d7549671c7189979f0624ec52dad9ea6a707d23146e3585ab8f8c4720eca0c63"

    strings:
        $proc_name1 = "slot_CPconfigdaemon" ascii
        $proc_name2 = "CPconfigdaemon" ascii
        $socket = ".p_sock" ascii
        $log = ".bd.log" ascii
        $upload = ".up.tpl" ascii
        $lib_inject = "libcpfwcommon.so" ascii

    condition:
        uint32(0) == 0x464c457f and
        (
            ($proc_name1) or
            ($proc_name2 and $socket) or
            ($proc_name2 and 2 of ($log, $upload, $lib_inject))
        )
}

rule PHP2Shell_WebShell_TPL
{
    meta:
        description = "Detects PHP web shells deployed via PHP2Shell exploitation on Check Point Mobile Access portals using the zz*.tpl pattern and hardcoded key"
        author = "Actioner"
        date = "2026-11-13"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        hash = "edb3e92eb7bda7413a09edcc4b1ba3cbed4bcdf42808a8abce63b6e4c3fda2b3"

    strings:
        $key = "zz2026" ascii
        $func1 = "system(" ascii
        $func2 = "eval(" ascii
        $func3 = "base64_decode(" ascii
        $upload_path = ".up.tpl" ascii
        $challenge = "challenge_render.tpl" ascii
        $xor_marker = "upload_progress_pwn" ascii

    condition:
        (
            $key and any of ($func1, $func2, $func3)
        ) or
        (
            $xor_marker and any of ($func1, $func2, $func3)
        ) or
        (
            $upload_path and $challenge and any of ($func1, $func2, $func3)
        )
}

rule Destroy_v6_Wiper
{
    meta:
        description = "Detects the destroy_v6 wiper tool used in destructive PHP2Shell/TSGA campaigns targeting Check Point and ESXi infrastructure"
        author = "Actioner"
        date = "2026-11-13"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        hash = "c7d9477309fac6c638a1128442056a242de086996add8cb49cd6496c36003237"

    strings:
        $note = "DREAM_ANNEXATION" ascii wide
        $name1 = "destroy_v6" ascii
        $name2 = "destory_v6" ascii
        $dream = "Dream Security" ascii wide

    condition:
        uint32(0) == 0x464c457f and
        (
            any of ($name1, $name2) or
            ($note and $dream)
        )
}

rule TSProxy_libcpfwcommon
{
    meta:
        description = "Detects the TSProxy shared library planted by TSGA to intercept networking functions in Check Point appliance processes"
        author = "Actioner"
        date = "2026-11-13"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        hash = "fb1a6235eb6bce8c9ec8cd8bb85f17c9c2bde8ecb45b7a243a30ceadf26654da"

    strings:
        $lib_name = "libcpfwcommon.so" ascii
        $related_lib = "libdssafe.so" ascii
        $socket = ".p_sock" ascii
        $proc = "slot_CPconfigdaemon" ascii

    condition:
        uint32(0) == 0x464c457f and
        $lib_name and
        any of ($related_lib, $socket, $proc)
}

rule PhiliKit_Philistine_Variant
{
    meta:
        description = "Detects the PhiliKit malware family (philistine variant) associated with Armory Castle / UNC5221 targeting network appliances"
        author = "Actioner"
        date = "2026-11-13"
        reference = "https://research.checkpoint.com/2026/php2shell-exploitation-on-check-point-gateway/"
        hash = "ee16e1695711b9d60c62925fcfb2fe1a29c18ae26565bc05410a14e16d2a39d7"

    strings:
        $s1 = "libdssafe.so" ascii
        $s2 = ".p_sock" ascii
        $s3 = "slot_CPconfigdaemon" ascii
        $s4 = "CPconfigdaemon" ascii
        $s5 = "libcpfwcommon.so" ascii

    condition:
        uint32(0) == 0x464c457f and
        3 of them
}
