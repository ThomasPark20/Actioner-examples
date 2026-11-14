rule Trojan_XMRig_4EverAble2Shell_Dropper
{
    meta:
        description = "Detects the jup.sh miner dropper script deployed through 4EverAble2Shell exploitation of N-central servers"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers"
        severity = "high"

    strings:
        $dir1 = "/tmp/.xvd" ascii
        $dir2 = "/var/tmp/.xvd" ascii
        $pool1 = "139.99.69" ascii
        $pool2 = "79.76.51" ascii
        $rig = "--rig-id nc_" ascii
        $donate = "--donate-level 1" ascii
        $beacon1 = "/ob/cronhit" ascii
        $beacon2 = "/ob/fcheck" ascii
        $keep = "keep.sh" ascii
        $xvd = "xvd.service" ascii

    condition:
        filesize < 500KB and
        5 of them
}
