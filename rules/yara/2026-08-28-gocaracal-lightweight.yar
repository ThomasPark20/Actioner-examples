rule APT_DarkCaracal_GoCaracal_Lightweight_RAT
{
    meta:
        description = "Detects GoCaracal lightweight RAT variant deployed by Dark Caracal, based on Go function names and internal strings identified by Arctic Wolf Labs"
        author = "Actioner"
        date = "2026-08-28"
        reference = "https://arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/"
        hash = "1e499c815146124c4a6d2b48c99068b980ad74e1a2cfd16013f8d75a9425a0ca"
        hash = "77f7ad29f4a8037ee5f38d3d87fb91cfd97cb8f7fa7883edf3fce506df5200c0"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $fn1 = "main.cleanupShell" ascii
        $fn2 = "main.handleConnection" ascii
        $fn3 = "main.detectAntivirus" ascii
        $fn4 = "main.saveFile" ascii
        $fn5 = "main.openUrl" ascii
        $fn6 = "main.smartSleep" ascii
        $fn7 = "main.runModule" ascii
        $fn8 = "main.InjectShellcode" ascii
        $fn9 = "main.injectShellcodeWoW64" ascii
        $fn10 = "main.handlePipeClient" ascii
        $fn11 = "main.loadAPIs" ascii
        $fn12 = "main.AntivirusProduct" ascii
        $fn13 = "main.lastInputInfo" ascii

        $s1 = "insensate" ascii
        $s2 = "readSecurePacket" ascii
        $s3 = "SendSecurePacket" ascii
        $s4 = "getRawOSVersion" ascii
        $s5 = "RPCFallback" ascii

    condition:
        filesize < 30MB and
        5 of them
}
