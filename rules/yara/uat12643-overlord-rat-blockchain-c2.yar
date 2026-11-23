/*
    YARA Rule: UAT-12643 Overlord RAT
    Author: Actioner Draft
    Date: 2026-11-23
    Description: Detects the Overlord RAT used by UAT-12643. The RAT is a Go binary
                 with Solana blockchain C2 resolution, WebSocket communication, and
                 BSoD anti-termination via NtSetInformationProcess.
    Reference: https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
    Hash: b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c
*/

rule UAT12643_OverlordRAT
{
    meta:
        author = "Actioner Draft"
        date = "2026-11-23"
        description = "Detects UAT-12643 Overlord RAT binary indicators"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c"
        threat_actor = "UAT-12643"
        malware_family = "Overlord RAT"
        confidence = "high"

    strings:
        // Solana RPC method calls for C2 resolution
        $solana_rpc1 = "getSignaturesForAddress" ascii wide
        $solana_rpc2 = "getTransaction" ascii wide
        $solana_memo = "jsonParsed" ascii wide

        // WebSocket C2 communication patterns
        $ws1 = "ws://" ascii wide
        $ws2 = "wss://" ascii wide
        $ws_port = ":5173" ascii

        // Anti-termination via NtSetInformationProcess
        $bsod1 = "NtSetInformationProcess" ascii wide
        $bsod2 = "SeDebugPrivilege" ascii wide
        $bsod3 = "ProcessBreakOnTermination" ascii wide

        // Go binary patterns typical of Overlord RAT
        $go_build = "win-8oa3ccqae4d" ascii
        $go_main = "main.main" ascii

        // WinRE persistence strings
        $winre1 = "\\Recovery\\OEM\\" ascii wide
        $winre2 = "ResetConfig.xml" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 30MB and
        (
            (2 of ($solana_rpc*) and any of ($ws*)) or
            (all of ($bsod*) and (any of ($solana_rpc*) or any of ($winre*))) or
            ($go_build and any of ($solana_rpc*)) or
            (any of ($winre*) and any of ($solana_rpc*))
        )
}

/*
    YARA Rule: UAT-12643 Good Game Stealer
    Author: Actioner Draft
    Date: 2026-11-23
    Description: Detects the Good Game infostealer distributed by UAT-12643.
                 PyInstaller-packed Python stealer targeting browsers, crypto wallets,
                 and gaming platforms.
    Reference: https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
*/

rule UAT12643_GoodGameStealer
{
    meta:
        author = "Actioner Draft"
        date = "2026-11-23"
        description = "Detects UAT-12643 Good Game Stealer artifacts"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash1 = "16622bb8df60403217ccf8e326e2e9e718e01c85d7b52fe5c5e1cf44d62d25c8"
        hash2 = "5a52d6773840fd5ab45d781d572d9fbd6a8dacb08dcda65036ce8b28548a5224"
        hash3 = "b0b636f5c7e40af94aacf9ebd9a696dac57debcd628127414248908562380d33"
        threat_actor = "UAT-12643"
        malware_family = "Good Game Stealer"
        confidence = "high"

    strings:
        // Core stealer script names
        $pyc1 = "final_build" ascii wide
        $pyc2 = "kora" ascii wide

        // Exfiltration indicators
        $exfil1 = "upload.gofile.io" ascii wide
        $exfil2 = "/uploadFile" ascii wide
        $exfil3 = "discord" ascii wide
        $exfil4 = "webhook" ascii wide

        // Persistence value
        $persist = "Zoipers" ascii wide

        // Stealer targets - crypto wallets
        $wallet1 = "Exodus" ascii wide
        $wallet2 = "Electrum" ascii wide
        $wallet3 = "Ledger Live" ascii wide
        $wallet4 = "Atomic" ascii wide

        // Discord token theft pattern
        $discord_token = "dQw4w9WgXcQ" ascii wide

        // System info collection
        $sysinfo = "system_infos.txt" ascii wide

        // Archive prefix
        $archive = "SK_" ascii

        // VM detection - sandbox DLLs
        $vm1 = "sbiedll.dll" ascii wide
        $vm2 = "vmcheck.dll" ascii wide
        $vm3 = "wpespy.dll" ascii wide

        // Geolocation check
        $geo = "ipwhois.app" ascii wide

        // Task Manager disable
        $taskmgr = "DisableTaskMgr" ascii wide

        // PyInstaller marker
        $pyinst = "MEI" ascii

    condition:
        (
            uint16(0) == 0x5A4D and
            filesize < 50MB and
            (
                (2 of ($exfil*) and any of ($wallet*)) or
                ($persist and any of ($exfil*)) or
                ($discord_token and any of ($exfil*)) or
                ($sysinfo and $archive and any of ($exfil*)) or
                (3 of ($vm*) and any of ($exfil*) and $pyinst)
            )
        ) or
        (
            // Python source detection
            (3 of ($exfil*) and $sysinfo and 2 of ($wallet*) and $taskmgr)
        )
}

/*
    YARA Rule: UAT-12643 Clipboard Hijacker
    Author: Actioner Draft
    Date: 2026-11-23
    Description: Detects the clipboard hijacker used by UAT-12643 to swap
                 cryptocurrency wallet addresses. C++ x64 binary with XOR-encrypted
                 replacement addresses.
    Reference: https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
*/

rule UAT12643_ClipboardHijacker
{
    meta:
        author = "Actioner Draft"
        date = "2026-11-23"
        description = "Detects UAT-12643 clipboard hijacker binary"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "f1e5174084bfded283b9dcf081615478e6941d12b652793197556beb72cc7588"
        threat_actor = "UAT-12643"
        malware_family = "Clipboard Hijacker"
        confidence = "high"

    strings:
        // Mutex name
        $mutex = "UuuRjinBZPBMIjnc" ascii wide

        // Persistence path
        $persist_path = "MsgEdgeUpdate.exe" ascii wide
        $persist_key = "MsgEdgeUpdate" ascii wide

        // Clipboard API usage patterns
        $clip1 = "OpenClipboard" ascii
        $clip2 = "GetClipboardData" ascii
        $clip3 = "SetClipboardData" ascii
        $clip4 = "EmptyClipboard" ascii

        // VM detection DLLs
        $vm1 = "sbiedll.dll" ascii
        $vm2 = "api_log.dll" ascii
        $vm3 = "cmdvrt64.dll" ascii

        // Hidden and system attributes
        $attrib = "attrib" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($mutex) or
            ($persist_path and 3 of ($clip*)) or
            ($persist_key and 3 of ($clip*) and any of ($vm*))
        )
}

/*
    YARA Rule: UAT-12643 MSBuild XML Downloader
    Author: Actioner Draft
    Date: 2026-11-23
    Description: Detects the malicious MSBuild XML file (dl.xml) used by UAT-12643
                 containing an inline C# task with a spoofed BITS user-agent.
    Reference: https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
*/

rule UAT12643_MSBuild_Downloader_XML
{
    meta:
        author = "Actioner Draft"
        date = "2026-11-23"
        description = "Detects UAT-12643 MSBuild inline C# downloader XML"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash = "19ca4e0e8e7dd62d130afbfed49646f1566dce2633cf937b848d990da3e3e9a2"
        threat_actor = "UAT-12643"
        malware_family = "MSBuild Downloader"
        confidence = "high"

    strings:
        $msbuild1 = "CodeTaskFactory" ascii nocase
        $msbuild2 = "UsingTask" ascii nocase
        $msbuild3 = "Microsoft.Build" ascii nocase
        $bits_ua = "Microsoft BITS/7.8" ascii wide
        $http = "WebClient" ascii
        $download = "DownloadFile" ascii nocase
        $download2 = "DownloadString" ascii nocase
        $download3 = "DownloadData" ascii nocase

    condition:
        filesize < 1MB and
        2 of ($msbuild*) and
        $bits_ua and
        ($http and any of ($download*))
}
