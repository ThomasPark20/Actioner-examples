rule CHOSEN_BRICK_HEAVYGRAM_Implant
{
    meta:
        author = "Actioner"
        description = "Detects CHOSEN BRICK/HEAVYGRAM persistent implant samples based on unique strings, mutexes, and code patterns from FBI FLASH-20260915"
        date = "2026-09-16"
        reference = "https://www.ic3.gov/CSA/2026/260915.pdf"
        hash1 = "8B595258CFF63C4F0EF9648ADB54C6AB050BB1D27933ECB3D687D31B51B7BA0C"
        hash2 = "4A3B003994112B4DD24AC8B9CC4757F4A12576B57B3CC8F5028D85FBCEB7C405"
        hash3 = "0D74156089292EEE308017C8E8A7550739ECB6149FF379810F7C54B1DBAABC91"
        hash4 = "C2DD678511373DC07E73EF1A580FC3332E640F15FF0D4C1044D4B9F305B6F503"

    strings:
        $mutex1 = "euyrsmnszb85sf4444s" ascii wide
        $mutex2 = "nih6723443489kcvrf" ascii wide
        $mutex3 = "ytyjyujyu" ascii wide
        $mutex4 = "noi672pp434awkc12f" ascii wide

        $path1 = "ZlibDate\\Z84A847FEEB1FC2s" ascii wide
        $path2 = "ZlibDate\\Settings\\config.xml" ascii wide
        $path3 = "ZlibDate\\CachedFiles" ascii wide
        $path4 = "SMQDServicePackages\\488ht1-8ww648q" ascii wide
        $path5 = "MicrosoftDistribution\\sysmain" ascii wide
        $path6 = "ssh-cache-default\\{8bda3848-495e-43f4-8d10-7d37a67f1604}" ascii wide

        $cmd1 = "ProcessList" ascii
        $cmd2 = "SendFile" ascii
        $cmd3 = "DefaultTelegram" ascii
        $cmd4 = "AllTelegram" ascii
        $cmd5 = "StoreTelegram" ascii
        $cmd6 = "GetChromeTelWhat" ascii
        $cmd7 = "GetMyWhatSesion" ascii
        $cmd8 = "OutlookExtract" ascii
        $cmd9 = "EnableMic" ascii
        $cmd10 = "SugWhatsapp" ascii
        $cmd11 = "GetChromePass" ascii
        $cmd12 = "ChangeSnapTime" ascii
        $cmd13 = "ChangeVicName" ascii

        $api1 = "api.telegram.org/bot" ascii wide
        $api2 = "vultrobjects.com" ascii wide

        $file1 = "rantom.txt" ascii wide
        $file2 = "chrome_passwords.json" ascii wide
        $file3 = "WhatssApp.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($mutex*) or
            2 of ($path*) or
            4 of ($cmd*) or
            (1 of ($api*) and 1 of ($path*)) or
            (1 of ($file*) and 1 of ($path*))
        )
}

rule CHOSEN_BRICK_MicDriver
{
    meta:
        author = "Actioner"
        description = "Detects CHOSEN BRICK MicDriver audio/screen surveillance module based on unique namespace strings and file paths"
        date = "2026-09-16"
        reference = "https://www.ic3.gov/CSA/2026/260915.pdf"
        hash1 = "168A487F0E44FFEE975ECD27D3F4000C750E711963A61D6CE244FA390DD17441"

    strings:
        $ns1 = "ZoomRecorder" ascii wide
        $ns2 = "getMState4" ascii wide
        $cfg1 = "C:\\ProgramData\\Drivers\\MicDriver\\Cache" ascii wide
        $cfg2 = "C:\\ProgramData\\ZlibDate\\Z84A847FEEB1FC2s\\Records" ascii wide
        $cfg3 = "C:\\ProgramData\\Drivers\\MicDriver" ascii wide
        $rar = "-pLoLoLoLo" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($ns*) and 1 of ($cfg*)) or
            ($rar and 1 of ($cfg*))
        )
}

rule CHOSEN_BRICK_Masquerading_Stage1
{
    meta:
        author = "Actioner"
        description = "Detects CHOSEN BRICK stage-1 masquerading droppers (Pictory, Telegram Authenticator) compiled with Embarcadero Delphi"
        date = "2026-09-16"
        reference = "https://www.ic3.gov/CSA/2026/260915.pdf"
        hash1 = "E8B633DCAD173EB41EF02686B46779A4A0E53DF7F6C63039A798F2DB5EB83AFC"
        hash2 = "9014FE4F16F01C0439B261ADE4CF980F460E0DAE46B1EC5F58FD9BC0AF26E531"

    strings:
        $cred = "ghazalehmehrjo@gmail.com" ascii wide
        $pwd = "8384238Fm@#$%^&*" ascii wide
        $drop1 = "SMQDServicePackages" ascii wide
        $drop2 = "downloaded_file26.txt" ascii wide
        $drop3 = "File26.zip" ascii wide
        $drop4 = "ssh-cache-default" ascii wide
        $drop5 = "Runtime_SSH.zip" ascii wide
        $drop6 = "RuntimeSSH.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            $cred or
            $pwd or
            2 of ($drop*)
        )
}

rule CHOSEN_BRICK_MsCache_Gmail
{
    meta:
        author = "Actioner"
        description = "Detects CHOSEN BRICK MsCache.exe Gmail OAuth token stealer module"
        date = "2026-09-16"
        reference = "https://www.ic3.gov/CSA/2026/260915.pdf"
        hash1 = "4908C0BC11A933D83C83935D9468BA8D08BC23529E5FF4D4344D4F0787B84BB6"

    strings:
        $path1 = "C:\\ProgramData\\ZlibDate\\CachedFiles\\" ascii wide
        $path2 = "Google\\Chrome\\Settings\\User Data" ascii wide
        $path3 = "credentials.json" ascii wide
        $scope = "https://mail.google.com/" ascii wide
        $pickle = ".pickle" ascii wide
        $err = "C:\\ProgramData\\ZlibDate\\CachedFiles\\er.txt" ascii wide
        $api = "api.telegram.org" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($path1, $path2, $err)) and
        2 of them
}
