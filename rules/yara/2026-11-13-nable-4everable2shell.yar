rule Nable_4EverAble2Shell_Privesc_Script
{
    meta:
        id = "c3a2e9f7-1b84-4d6e-a530-2f9c7d08e143"
        author = "Actioner"
        date = "2026-11-13"
        description = "Detects the Python privilege escalation script used in 4EverAble2Shell post-exploitation to escalate from nable to root via ServerChild.sh symlink manipulation"
        reference = "https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers"
        hash = "fc4c01fd11bc301cf312830460cfdccc3af9dcfe50c910b86d6a1117bc76c747"
        severity = "critical"

    strings:
        $path1 = "/var/opt/n-central/flag/flag_default.json" ascii
        $path2 = "/opt/nable/var/ncsai/scripts/ServerChild.sh" ascii
        $path3 = "/var/opt/n-central/tmp/serverchild-" ascii
        $cmd1  = "nable_wrapper.pl" ascii
        $cmd2  = "setLDFileOwner" ascii
        $cmd3  = "serverControl noop" ascii
        $marker1 = "write_before" ascii
        $marker2 = "write_after" ascii
        $marker3 = "helper_restored" ascii

    condition:
        uint16(0) != 0x5A4D and
        (
            ($path1 and $path2) or
            ($cmd1 and $cmd2 and $cmd3) or
            ($path3 and ($marker1 or $marker2 or $marker3)) or
            (4 of them)
        )
}

rule Nable_4EverAble2Shell_Miner_Installer_JupSh
{
    meta:
        id = "a7f13e84-5d29-4c6b-90a2-bc4e87d15f23"
        author = "Actioner"
        date = "2026-11-13"
        description = "Detects the jup.sh miner installer script used in 4EverAble2Shell post-exploitation to deploy XMRig on compromised N-central servers"
        reference = "https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers"
        severity = "critical"

    strings:
        $dir1   = "/tmp/.xvd" ascii
        $dir2   = "/var/tmp/.xvd" ascii
        $pool1  = "139.99.69.109" ascii
        $pool2  = "79.76.51.56" ascii
        $c2     = "157.20.241.16" ascii
        $rigpfx = "nc_" ascii
        $beacon = "/ob/cronhit" ascii
        $check  = "/ob/fcheck" ascii
        $keep   = "keep.sh" ascii
        $svc    = "xvd.service" ascii
        $tag    = "xvkeep" ascii
        $hint   = "--cpu-max-threads-hint" ascii

    condition:
        filesize < 50KB and
        (
            ($dir1 and ($pool1 or $pool2)) or
            ($c2 and ($beacon or $check)) or
            ($svc and $tag and $keep) or
            (5 of them)
        )
}

rule Nable_4EverAble2Shell_SOAP_Exploit_Payload
{
    meta:
        id = "f28d6c01-93a7-4e5f-b184-7e0a52c3d961"
        author = "Actioner"
        date = "2026-11-13"
        description = "Detects SOAP exploit payloads targeting N-central Apache Axis via jline.internal.TerminalLineSettings class instantiation, the initial access vector for 4EverAble2Shell"
        reference = "https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers"
        severity = "critical"

    strings:
        $soap    = "<soapenv:" ascii nocase
        $fault   = "exceptionName" ascii
        $jline   = "jline.internal.TerminalLineSettings" ascii
        $axis    = "ServerUI" ascii

    condition:
        filesize < 100KB and
        $jline and ($soap or $fault) and $axis
}
