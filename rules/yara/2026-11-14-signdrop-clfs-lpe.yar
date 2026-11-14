rule Exploit_SignDrop_CLFS_LPE
{
    meta:
        description = "Detects the SignDrop exploit tool that abuses CLFS logfile authentication for SYSTEM privilege escalation via path redirection and Defender signature update abuse"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://github.com/MSNightmare/SignDrop"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $name1 = "SigDrop" ascii wide
        $name2 = "SignDrop" ascii wide

        $dir1 = "SigDrop_" ascii wide
        $dir2 = "\\microsoft shared\\ink\\hid.dll" ascii wide

        $api1 = "ServerMpUpdateEngineSignature" ascii wide
        $api2 = "AddLogContainer" ascii fullword
        $api3 = "NtCreateFile" ascii fullword
        $api4 = "DeviceIoControl" ascii fullword

        $rpc1 = "windefend" ascii wide nocase
        $rpc2 = "Proc42" ascii wide

        $file1 = "hid.dll" ascii wide
        $file2 = "MpEngine.dll" ascii wide
        $file3 = ".cnpf" ascii wide
        $file4 = ".blf" ascii wide

        $path1 = "\\BaseNamedObjects\\Restricted\\" ascii wide
        $path2 = "mpasbase.vdm" ascii wide
        $path3 = "WinSta0\\Default" ascii wide

        $ioctl1 = { 08 A8 07 80 }

        $res1 = "IDR_DLL1" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (1 of ($name*) and 1 of ($api1, $api2) and 1 of ($file*)) or
            ($dir1 and $dir2) or
            ($api1 and 1 of ($path*)) or
            ($dir1 and $api1) or
            ($dir1 and 2 of ($file*) and 1 of ($api*)) or
            (1 of ($name*) and $ioctl1 and 1 of ($path*)) or
            ($res1 and $dir1 and 1 of ($file*)) or
            ($dir2 and $api1) or
            (1 of ($rpc*) and $dir1 and 1 of ($file*))
        )
}

rule Exploit_SignDrop_Planted_HID_DLL
{
    meta:
        description = "Detects a planted hid.dll payload potentially associated with the SignDrop exploit chain, which places a malicious DLL in the Ink directory for consent.exe to load"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://github.com/MSNightmare/SignDrop"
        severity = "medium"
        tlp = "WHITE"

    strings:
        $s1 = "SigDrop" ascii wide
        $s2 = "SignDrop" ascii wide
        $s3 = "conhost" ascii wide
        $s4 = "WinSta0" ascii wide
        $s5 = "consent" ascii wide
        $s6 = "IDR_DLL1" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (1 of ($s1, $s2, $s6)) and (2 of them)
}
