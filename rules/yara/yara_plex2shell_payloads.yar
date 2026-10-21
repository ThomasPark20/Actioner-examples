rule Plex2Shell_XMRig_Miner_x12345 {
    meta:
        description = "Detects the XMRig miner binary (x12345/x) dropped during Plex2Shell exploitation campaigns"
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://www.boredhackerblog.info/2026/10/plex-vulnerabilities-being-exploited-in.html"
        hash_packed = "68938fb428f2bcfef4ede62f7b29cd0f15f37ed59e94462c099f2ca64e36baa7"
        hash_unpacked = "b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49"
        hash_xmrig = "2d3c618b21a7e2f8bcd735da188e44a7609ff3f204832dd0781cd09e4388c9db"
    strings:
        $upx = "UPX!" ascii
        $miner1 = "stratum+tcp://" ascii
        $miner2 = "cryptonight" ascii nocase
        $miner3 = "xmrig" ascii nocase
        $pool = "ota.proxystream.st" ascii
        $name1 = "mylovelyminer" ascii
        $name2 = "x12345" ascii
    condition:
        uint32(0) == 0x464C457F and
        (
            ($upx and any of ($miner*)) or
            ($pool) or
            ($name1) or
            ($name2 and any of ($miner*)) or
            (2 of ($miner*))
        )
}

rule Plex2Shell_Proxy_Backdoor_myawesomeproxy {
    meta:
        description = "Detects the myawesomeproxy reverse proxy backdoor deployed during Plex2Shell exploitation"
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://www.boredhackerblog.info/2026/10/plex-vulnerabilities-being-exploited-in.html"
        hash = "e546b10aee5edc754da4f9b0baace00392257121911f630145078eafad1e6bd9"
    strings:
        $banner = "Running this software on any of your devices makes you agree to the potential external use of your internet traffic" ascii
        $name = "myawesomeproxy" ascii
        $relay = "global.relay.proxystream.st" ascii
        $domain = "proxystream.st" ascii
    condition:
        uint32(0) == 0x464C457F and
        (
            ($banner) or
            ($name and $domain) or
            ($relay)
        )
}

rule Plex2Shell_Malicious_Codec_SO {
    meta:
        description = "Detects malicious ELF shared objects planted in the Plex Codecs directory via CVE-2026-96656"
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://zmain.info/blog/plex2shell"
    strings:
        $plex_path = "Plex Media Server" ascii
        $codecs = "Codecs" ascii
        $init_array = ".init_array" ascii
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $wget = "wget " ascii
        $curl = "curl " ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize < 100KB and
        (
            ($init_array and any of ($shell*)) or
            ($plex_path and $codecs and any of ($shell*, $wget, $curl))
        )
}

rule Plex2Shell_Docker_Dropper {
    meta:
        description = "Detects the docker dropper binary used in the Plex2Shell exploitation campaign"
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://www.boredhackerblog.info/2026/10/plex-vulnerabilities-being-exploited-in.html"
        hash = "5712ef510481f15fe8b18fdd10b73026d57cb3d9d151878a692358b99a464441"
    strings:
        $s1 = "myawesomeproxy" ascii
        $s2 = "mylovelyminer" ascii
        $s3 = "proxystream.st" ascii
        $dl1 = "wget " ascii
        $dl2 = "curl " ascii
    condition:
        uint32(0) == 0x464C457F and
        (
            (2 of ($s*)) or
            (any of ($s*) and any of ($dl*))
        )
}
