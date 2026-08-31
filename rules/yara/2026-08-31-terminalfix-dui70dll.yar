rule Malware_TerminalFix_dui70_DLL
{
    meta:
        description = "Detects dui70.dll variants used in the TerminalFix ClickFix campaign for DLL sideloading via LockScreenContentServer.exe"
        author = "Actioner"
        date = "2026-08-31"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        severity = "critical"
        tlp = "white"

    strings:
        $dll_name = "dui70.dll" ascii wide
        $path1 = "\\ProgramData\\f47f2a8c21c9df4e" ascii wide
        $path2 = "LockScreenContentServer" ascii wide
        $bat = "1.bat" ascii wide

        $py_tunnel1 = "client.py" ascii wide
        $py_tunnel2 = "pythonw.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (2 of ($path*, $dll_name, $bat)) or
            ($dll_name and $py_tunnel1) or
            ($path1 and 1 of ($py_tunnel*))
        )
}
