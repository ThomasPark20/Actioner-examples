rule TerminalFix_Python_Tunnel_Implant
{
    meta:
        description = "Detects the TerminalFix Python-based reverse tunnel implant (client.py) via characteristic strings"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        hash = "b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a"
        severity = "critical"

    strings:
        $s1 = "Extract-RawFileFromImage" ascii wide
        $s2 = "gitnow.dev" ascii wide
        $s3 = "client.py" ascii
        $s4 = "--server" ascii
        $s5 = "--uuid" ascii
        $s6 = "cert.pem" ascii
        $s7 = "/tunnel" ascii
        $s8 = "CERT_NONE" ascii
        $s9 = "bestsocialmedianewspapper.com" ascii wide
        $s10 = "offlineupdater.com" ascii wide

    condition:
        filesize < 500KB and
        (
            (3 of ($s1, $s2, $s7, $s8, $s9, $s10)) or
            ($s3 and $s4 and $s5 and $s6) or
            ($s2 and $s7 and $s8)
        )
}

rule TerminalFix_Malicious_DUI70_DLL
{
    meta:
        description = "Detects the TerminalFix malicious dui70.dll used in DLL sideloading with LockScreenContentServer.exe"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        hash = "ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07"
        severity = "critical"

    strings:
        $dll_name = "dui70.dll" ascii wide fullword
        $steg1 = "Extract-RawFileFromImage" ascii wide
        $steg2 = "RGBA" ascii
        $c2_1 = "gitnow.dev" ascii wide
        $c2_2 = "bestsocialmedianewspapper.com" ascii wide
        $c2_3 = "offlineupdater.com" ascii wide
        $persist1 = "LockScreenContentServer" ascii wide
        $bat = "1.bat" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (2 of ($c2_*)) or
            ($steg1 and 1 of ($c2_*)) or
            ($steg2 and $steg1) or
            ($dll_name and $persist1 and $bat and 1 of ($c2_*))
        )
}
