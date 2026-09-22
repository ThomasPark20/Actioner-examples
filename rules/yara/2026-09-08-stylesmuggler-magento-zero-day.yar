rule Malware_StyleSmuggler_Rust_Implant
{
    meta:
        description = "Detects the StyleSmuggler (CVE-2026-75650) Rust-based Linux implant family (kworker/fc-cache/chronyd masquerading builds) via embedded C2 and IP-discovery domain strings and process-masquerade markers"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://sansec.io/research/stylesmuggler-0day"
        reference2 = "https://github.com/disrex-group/stylesmuggler-mitigation/blob/main/IOC.md"
        hash1 = "e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7"
        hash2 = "8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef"
        hash3 = "251fabd50d7b18a8b5e1b3ef5d64e7198c17244778f6461fb1ab07f6169bf220"
        hash4 = "b79dfdc1eed860e0b76c629d6adfce251db379b0b45a6d728d4ef483f7551420"
        hash5 = "4352cabaa451e5a894535fbcc4d46628701303322a13745cb5479d7d0534ae8e"
        hash6 = "d2fbf9eb75c495bfea48790d3b228fab0c15a282419c3d3f5e49294c4e1a3e82"
        tlp = "CLEAR"
        severity = "critical"

    strings:
        $c2_1 = "ntp.timesync.to" ascii
        $c2_2 = "ntp.timesysnc.net" ascii
        $c2_3 = "windwsecurity.run" ascii
        $c2_4 = "time.microsft.run" ascii
        $c2_5 = "pool.microsft.studio" ascii
        $c2_6 = "ntp.synctime.to" ascii
        $c2_7 = "ntp.syncstime.to" ascii

        $ipdisc_1 = "api4.ipify.org" ascii
        $ipdisc_2 = "ipv4.icanhazip.com" ascii
        $ipdisc_3 = "ipv4.ident.me" ascii

        $mask_1 = "[kworker/u:8:0]" ascii
        $mask_2 = ".gvfsd/gvfsd-user" ascii
        $mask_3 = ".cache/fontconfig/fc-cache" ascii
        $mask_4 = ".chrony-" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize > 500KB and filesize < 4MB and
        (
            3 of ($c2_*) or
            (1 of ($c2_*) and 1 of ($ipdisc_*)) or
            (1 of ($c2_*) and 1 of ($mask_*)) or
            2 of ($mask_*)
        )
}

rule Backdoor_StyleSmuggler_PHP_WebShell_Dropper
{
    meta:
        description = "Detects the compact PHP web-shell dropper placed via the StyleSmuggler (CVE-2026-75650) entry point by a secondary threat actor into pub/media/catalog/product/cache/ss_<hex>/sync_<hex>.php; gated by an X-Cache-Token header and a task POST parameter"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://securityaffairs.com/198603/uncategorized/stylesmuggler-the-magento-zero-day-behind-new-store-attacks.html"
        reference2 = "https://sansec.io/research/stylesmuggler-0day"
        hash = "d61217ca0bca83204302fa7b41935ce36f73764559c156d5c980f2fedddffb6e"
        tlp = "CLEAR"
        severity = "critical"

    strings:
        $php_open = "<?php" ascii
        $header = "X-Cache-Token" ascii
        $token = "fced27f6d57702565353ecc11722533b" ascii
        $param = "task" ascii
        $notfound = "404" ascii

    condition:
        filesize < 2KB and
        $php_open and
        $header and
        2 of ($token, $param, $notfound)
}
