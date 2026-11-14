rule Trojan_XMRig_4EverAble2Shell_Config
{
    meta:
        description = "Detects XMRig miner configuration associated with the 4EverAble2Shell campaign targeting N-central servers, including wallet address and pool indicators"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://huntback.io/blog/ncentral-4everable2shell-miners-on-live-servers"
        severity = "high"

    strings:
        $wallet = "41wx2Pv3FzfRvX11jQgzM4bRbgvr6GViRXCKkHhXhLVQ64mgUR5ks4CEzHx8zqUJ8MgsWwTaWiS3uiZbCgJQnNXoB19mGtr" ascii
        $pool1 = "139.99.69.109:10128" ascii
        $pool2 = "79.76.51.56:39100" ascii
        $rig_prefix = "nc_" ascii

    condition:
        filesize < 10MB and
        ($wallet or (1 of ($pool*) and $rig_prefix))
}
