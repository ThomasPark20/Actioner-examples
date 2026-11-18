import "pe"

rule Malware_OverlordRAT_Go_Binary : UAT12643
{
    meta:
        description = "Detects Overlord RAT Go-compiled Windows RAT used by UAT-12643. Matches anti-termination, WinRE persistence, and Solana C2 resolution strings."
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c"
        severity = "critical"

    strings:
        $go1 = "Go build" ascii
        $go2 = "runtime.main" ascii

        $anti1 = "SeDebugPrivilege" ascii wide
        $anti2 = "NtSetInformationProcess" ascii
        $anti3 = "ProcessBreakOnTermination" ascii

        $persist1 = "\\Recovery\\OEM\\" ascii wide
        $persist2 = "ResetConfig.xml" ascii wide
        $persist3 = "CurrentVersion\\Run" ascii wide

        $solana1 = "getSignatures" ascii
        $solana2 = "getTransaction" ascii
        $solana3 = "jsonParsed" ascii

        $ws1 = "websocket" ascii nocase
        $ws2 = "5173" ascii

        $cmd1 = "GetAsyncKeyState" ascii
        $cmd2 = "keylog" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 30MB and
        1 of ($go*) and
        (
            (2 of ($anti*) and 1 of ($persist*)) or
            (2 of ($solana*)) or
            (1 of ($anti*) and 1 of ($solana*) and 1 of ($ws*)) or
            (2 of ($anti*) and 1 of ($cmd*))
        )
}

rule Malware_GoodGame_Infostealer_Python : UAT12643
{
    meta:
        description = "Detects Good Game infostealer Python scripts used by UAT-12643. Matches stealer logic, sandbox checks, and exfiltration patterns."
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "b0b636f5c7e40af94aacf9ebd9a696dac57debcd628127414248908562380d33"
        severity = "high"

    strings:
        $pyinst1 = "PyInstaller" ascii
        $pyinst2 = "_MEIPASS" ascii

        $sb1 = "sbiedll.dll" ascii nocase
        $sb2 = "api_log.dll" ascii nocase
        $sb3 = "vmcheck.dll" ascii nocase
        $sb4 = "wpespy.dll" ascii nocase
        $sb5 = "cmdvrt64.dll" ascii nocase

        $steal1 = "ROBLOSECURITY" ascii
        $steal2 = "dQw4w9WgXcQ:" ascii
        $steal3 = "upload.gofile.io" ascii
        $steal4 = "uploadFile" ascii
        $steal5 = "ipwhois.app" ascii

        $pers1 = "Zoipers" ascii
        $pers2 = "DisableTaskMgr" ascii

        $file1 = "final_build" ascii
        $file2 = "kora" ascii

    condition:
        filesize < 50MB and
        (
            (2 of ($sb*) and 2 of ($steal*)) or
            (1 of ($pyinst*) and 2 of ($steal*) and 1 of ($pers*)) or
            (1 of ($file*) and 2 of ($steal*))
        )
}

rule Malware_ClipboardHijacker_WalletClipper : UAT12643
{
    meta:
        description = "Detects UAT-12643 multi-cryptocurrency clipboard hijacker. Matches mutex, anti-VM checks, and clipboard monitoring behavior."
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "f1e5174084bfded283b9dcf081615478e6941d12b652793197556beb72cc7588"
        severity = "high"

    strings:
        $mutex = "UuuRjinBZPBMIjnc" ascii wide
        $file1 = "MsgEdgeUpdate" ascii wide

        $vm1 = "VBOX" ascii wide
        $vm2 = "VMWARE" ascii wide
        $vm3 = "QEMU" ascii wide
        $vm4 = "SANDBOX" ascii wide

        $clip1 = "OpenClipboard" ascii
        $clip2 = "GetClipboardData" ascii
        $clip3 = "SetClipboardData" ascii
        $clip4 = "CloseClipboard" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $mutex or
            ($file1 and 2 of ($clip*)) or
            ($file1 and 2 of ($vm*) and 2 of ($clip*))
        )
}

rule Malware_UAT12643_HTA_Dropper : UAT12643
{
    meta:
        description = "Detects HTA dropper files used by UAT-12643 for initial payload delivery via mshta.exe"
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "c8f9ce4b58acec3ce5640041cbc6d4802e30b2dded4a88766ee2de2cefde45f7"
        severity = "high"

    strings:
        $hta1 = "<HTA:APPLICATION" ascii nocase
        $hta2 = "MSXML2.ServerXMLHTTP" ascii nocase
        $hta3 = "ADODB.Stream" ascii nocase
        $path1 = "\\Temp\\s.exe" ascii

    condition:
        filesize < 500KB and
        $hta1 and
        ($hta2 and $hta3) and
        $path1
}

rule Malware_UAT12643_MSBuild_Inline_Task : UAT12643
{
    meta:
        description = "Detects dl.xml MSBuild inline task used by UAT-12643 with spoofed BITS User-Agent"
        author = "Actioner"
        date = "2026-11-18"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "19ca4e0e8e7dd62d130afbfed49646f1566dce2633cf937b848d990da3e3e9a2"
        severity = "high"

    strings:
        $xml1 = "CodeTaskFactory" ascii
        $xml2 = "UsingTask" ascii
        $ua = "Microsoft BITS/7.8" ascii

    condition:
        filesize < 1MB and
        $xml1 and $xml2 and
        $ua
}
