rule Malware_CornFlake_RAT_CaptiveCrunch
{
    meta:
        description = "Detects CornFlake RAT (Go-based) used by Storm-2945 in the CaptiveCrunch campaign via distinctive strings"
        author = "Actioner"
        date = "2026-08-02"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        hash = "918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593"
        severity = "critical"

    strings:
        $svc_name = "svchost32" ascii wide
        $svc_display = "Cloud Sync Service" ascii wide
        $svc_desc = "Synchronizes files with the cloud storage provider" ascii wide
        $cfg_file = "sync.dat" ascii wide
        $api_upload = "/upload" ascii
        $api_reload = "/reload" ascii
        $api_status = "/status" ascii
        $dropper1 = "winupdate" ascii
        $dropper2 = "directx" ascii
        $dropper3 = "vcredist" ascii
        $dropper4 = "sysopt" ascii
        $dropper5 = "netfix" ascii
        $path = "svchost32\\svchost32.exe" ascii wide

    condition:
        filesize < 20MB and
        (
            ($svc_name and $svc_display) or
            ($svc_name and $svc_desc) or
            ($path and 2 of ($dropper*)) or
            ($cfg_file and $svc_name and 2 of ($api*))
        )
}

rule Malware_ChocoShell_Stealer_CaptiveCrunch
{
    meta:
        description = "Detects ChocoShell PowerShell stealer used by Storm-2945 in the CaptiveCrunch campaign via distinctive C2 URI patterns and credential theft strings"
        author = "Actioner"
        date = "2026-08-02"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        hash = "be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c"
        severity = "critical"

    strings:
        $c2_beacon = "/t/pixel.gif?m=" ascii wide
        $c2_payload = "/cdn/chunks/polyfill-7e2b.min.js" ascii wide
        $c2_exfil = "/t/event" ascii wide
        $uac1 = "SilentCleanup" ascii wide
        $uac2 = "wsreset.exe" ascii wide
        $uac3 = "sdclt.exe" ascii wide
        $uac4 = "KickOffElev" ascii wide
        $token1 = ".tbres" ascii wide
        $token2 = "Token Broker" ascii wide
        $wifi = "key=clear" ascii wide

    condition:
        filesize < 5MB and
        (
            (2 of ($c2*)) or
            ($c2_beacon and 2 of ($uac*)) or
            ($c2_exfil and $token1 and $token2) or
            ($c2_beacon and $wifi and $token1)
        )
}
