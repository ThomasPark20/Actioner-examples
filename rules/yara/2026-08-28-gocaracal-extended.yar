rule APT_DarkCaracal_GoCaracal_Extended_RAT
{
    meta:
        description = "Detects GoCaracal extended RAT variant with Ethereum C2 fallback and post-compromise capabilities deployed by Dark Caracal"
        author = "Actioner"
        date = "2026-08-28"
        reference = "https://arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/"
        hash = "8c03d072df2e1bf14b0c00a8ab99834138c8b69f301849bf09cb44394e916015"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $fn1 = "main.InjectShellcode" ascii
        $fn2 = "main.smartSleep" ascii
        $fn3 = "main.detectAntivirus" ascii
        $fn4 = "main.handleConnection" ascii
        $fn5 = "main.loadAPIs" ascii

        $s1 = "RPCFallback" ascii
        $s2 = "SendSecurePacket" ascii
        $s3 = "readSecurePacket" ascii
        $s4 = "BulletproofC2" ascii
        $s5 = "eth_getStorageAt" ascii
        $s6 = "getRawOSVersion" ascii

        $eth1 = "0x03D605f13A74Bfb6149078122FcF62BD6d8799d8" ascii nocase
        $eth2 = "0x04aB453494381E60171BE04Ea6BE6E7C44EafAfd" ascii nocase
        $eth3 = "0xD7635f31620772882a6712472a6278c53247Bc44" ascii nocase
        $eth4 = "0xf165F26300BF65DFaC78BC9557326bDbB3C6d33C" ascii nocase

    condition:
        filesize < 30MB and
        (
            (3 of ($fn*) and 2 of ($s*)) or
            (any of ($eth*) and 1 of ($s*))
        )
}
