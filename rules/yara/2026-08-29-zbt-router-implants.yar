rule ZBT_SPEAKINGSTONE_yunmgrd
{
    meta:
        description = "Detects the SPEAKINGSTONE (yunmgrd) factory implant binary found in ZBT router firmware"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://vulncheck.com/blog/zbt-darklantern-speakingstone"
        hash = "b77811db4d218c65670a6c9a5b33c30ff81c6d779e15d658643138771178a818"
        severity = "critical"

    strings:
        $s1 = "zbtProtocol.c" ascii
        $s2 = "zbt protocol running" ascii
        $s3 = "/tmp/yunclient.conf" ascii
        $s4 = "cmcc_server" ascii
        $s5 = "dnshack" ascii
        $s6 = "/etc/exec/cmd" ascii
        $s7 = "setBackServer" ascii
        $s8 = "regMsg" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 1MB and
        4 of ($s*)
}

rule ZBT_DARKLANTERN_infosrvd
{
    meta:
        description = "Detects the DARKLANTERN (infosrvd) factory implant binary found in ZBT router firmware"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://vulncheck.com/blog/zbt-darklantern-speakingstone"
        hash = "7e2e036fec2fe7ab4bbd43978d9296563894c92a112f5ac2f39957f12108e245"
        severity = "critical"

    strings:
        $s1 = "/etc/exec/cmd " ascii
        $s2 = "/etc/exec/sysinfo" ascii
        $s3 = "/tmp/cmd.log" ascii
        $s4 = "/tmp/info.txt" ascii
        $s5 = "Salt_171006_808290505" ascii
        $s6 = "Allmac_171007_808290505" ascii
        $s7 = "startlocalserve" ascii
        $s8 = "invalid request pkt" ascii
        $s9 = "revProto" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 1MB and
        4 of ($s*)
}

rule ZBT_inetdetect_launcher
{
    meta:
        description = "Detects the inetdetect watchdog binary that launches both DARKLANTERN and SPEAKINGSTONE implants on ZBT routers"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://vulncheck.com/blog/zbt-darklantern-speakingstone"
        hash = "ae6c356f1f09260b859f84d994ef8423540a6c0bdf98510d86b85834283e4926"
        severity = "high"

    strings:
        $s1 = "yunmgrd" ascii
        $s2 = "infosrvd" ascii
        $s3 = "inetdetect" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 500KB and
        all of them
}
