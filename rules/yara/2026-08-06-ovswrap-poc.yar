rule Exploit_CVE_2026_64531_OVSwrap_PoC
{
    meta:
        description = "Detects the OVSwrap (CVE-2026-64531) proof-of-concept exploit script targeting Linux kernel Open vSwitch local privilege escalation"
        author = "Actioner"
        date = "2026-08-06"
        reference = "https://github.com/manizada/OVSwrap"
        severity = "critical"

    strings:
        $s1 = "ovswrap" ascii nocase
        $s2 = "CVE-2026-64531" ascii
        $s3 = "add_nested_action_end" ascii
        $s4 = "nla_len" ascii
        $s5 = "sw_flow_actions" ascii
        $s6 = "dst_release" ascii
        $s7 = "init_pid_ns" ascii
        $s8 = "tun_dst" ascii

        $cmd1 = "unshare -Urn" ascii
        $cmd2 = "/etc/sudoers" ascii
        $cmd3 = "aa-exec" ascii
        $cmd4 = "openvswitch" ascii
        $cmd5 = "nf_conntrack_ftp" ascii
        $cmd6 = "CAP_NET_ADMIN" ascii

        $poc1 = "ovswrap-poc" ascii
        $poc2 = "manizada" ascii
        $poc3 = "kernel_pointer_leak" ascii nocase
        $poc4 = "arbitrary_kernel_read" ascii nocase
        $poc5 = "targeted_decrement" ascii nocase
        $poc6 = "credential_corruption" ascii nocase

    condition:
        filesize < 5MB and
        (
            ($s1 and $s2) or
            ($poc1 and 2 of ($cmd*)) or
            (3 of ($s*) and 2 of ($cmd*)) or
            (3 of ($poc*))
        )
}
