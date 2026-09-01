rule Malware_TerminalFix_DUI70_Sideload_DLL
{
    meta:
        description = "Detects malicious dui70.dll variants used by the TerminalFix campaign for DLL sideloading via LockScreenContentServer.exe"
        author = "Actioner"
        date = "2026-09-01"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        hash1 = "ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07"
        hash2 = "026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab"
        hash3 = "032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22"
        hash4 = "df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf"
        hash5 = "eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0"
        hash6 = "5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8"
        hash7 = "9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24"
        hash8 = "342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e"
        hash9 = "ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d"
        severity = "high"

    strings:
        $dll_name = "dui70.dll" ascii wide
        $export1 = "InitProcessPriv" ascii
        $export2 = "InitThread" ascii
        $export3 = "UnInitThread" ascii
        $export4 = "CreateDUINode" ascii
        $steg1 = "Extract-RawFileFromImage" ascii wide
        $steg2 = "RGBA" ascii wide
        $invoke = "Invoke-Expression" ascii wide nocase
        $c2_1 = "gitnow.dev" ascii wide
        $c2_2 = "bestsocialmedianewspapper.com" ascii wide
        $c2_3 = "offlineupdater.com" ascii wide
        $path = "f47f2a8c21c9df4e" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($dll_name and 2 of ($export*) and ($invoke or 1 of ($steg*))) or
            (2 of ($c2*)) or
            ($path and ($dll_name or $invoke)) or
            ($dll_name and 1 of ($steg*) and 1 of ($c2*))
        )
}

rule Malware_TerminalFix_Python_Tunnel_Implant
{
    meta:
        description = "Detects the Python-based reverse tunnel implant (client.py) used by the TerminalFix campaign for WebSocket C2 tunneling"
        author = "Actioner"
        date = "2026-09-01"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        hash = "b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a"
        severity = "high"

    strings:
        $tunnel = "/tunnel" ascii
        $c2 = "gitnow.dev" ascii
        $cert = "CERT_NONE" ascii
        $ws1 = "websocket" ascii nocase
        $ws2 = "WebSocket" ascii
        $shutdown = "MSG_SHUTDOWN" ascii
        $keepalive = "keepalive" ascii
        $stream = "stream_id" ascii
        $uuid = "--uuid" ascii
        $server = "--server" ascii
        $pythonw = "pythonw" ascii
        $ua1 = "Chrome" ascii
        $ua2 = "Firefox" ascii
        $ua3 = "Safari" ascii

    condition:
        filesize < 500KB and
        (
            ($c2 and $tunnel and ($cert or 1 of ($ws*))) or
            ($shutdown and $keepalive and $stream) or
            ($c2 and $uuid and $server) or
            ($tunnel and $cert and 2 of ($ua*) and $stream) or
            ($pythonw and $c2 and $tunnel)
        )
}
