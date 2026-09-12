rule Malware_StyleSmuggler_Rust_Backdoor
{
    meta:
        description = "Detects the StyleSmuggler Rust-based Linux backdoor deployed via CVE-2026-75650 exploitation of Adobe Commerce / Magento. Matches known sample hashes and behavioral strings."
        author = "Actioner"
        date = "2026-09-12"
        reference = "https://sansec.io/research/stylesmuggler-0day"
        hash = "e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7"
        hash = "4352cabaa451e5a894535fbcc4d46628701303322a13745cb5479d7d0534ae8e"
        hash = "1a3374ffac5b0a62467612f264c49792d206304d4514409c982325c91231375d"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // Process name masquerade strings
        $proc1 = "[kworker/u:8:0]" ascii
        $proc2 = "fc-cache" ascii fullword
        $proc3 = "chronyd" ascii fullword

        // C2 domain indicators (defanged in meta, raw for scanning)
        $c2_1 = "windwsecurity.run" ascii
        $c2_2 = "ntp.timesync.to" ascii
        $c2_3 = "ntp.timesysnc.net" ascii
        $c2_4 = "time.microsft.run" ascii
        $c2_5 = "pool.microsft.studio" ascii
        $c2_6 = "ntp.synctime.to" ascii
        $c2_7 = "ntp.syncstime.to" ascii

        // File path artifacts
        $path1 = ".local/share/.gvfsd/gvfsd-user" ascii
        $path2 = ".cache/fontconfig/fc-cache" ascii
        $path3 = ".gvfsd_" ascii
        $path4 = ".fc_" ascii

        // Campaign markers
        $camp1 = "ss5_457cfa2fb7" ascii
        $camp2 = "ss6_457cfa2fb7" ascii

        // Malware download source
        $dl1 = "247.cdnflare.xyz" ascii
        $dl2 = "incofar.it" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            2 of ($c2_*) or
            1 of ($camp*) or
            (1 of ($proc*) and 1 of ($path*)) or
            (1 of ($c2_*) and 1 of ($path*)) or
            $dl1 or
            ($dl2 and 1 of ($c2_*))
        )
}
