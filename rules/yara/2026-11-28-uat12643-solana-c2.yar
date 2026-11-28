/*
    UAT-12643 / Overlord RAT / Good Game Stealer / Clipboard Hijacker
    Cisco Talos - November 2026
    Reference: https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
*/

rule UAT12643_Overlord_RAT
{
    meta:
        description = "Detects Overlord RAT (Go-based) used by UAT-12643. Keys on WebSocket C2 protocol strings, Solana blockchain C2 resolution methods, anti-analysis DLL names, and the BSoD self-protection mechanism (ProcessBreakOnTermination via NtSetInformationProcess)."
        author = "Actioner"
        date = "2026-11-28"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash1 = "b7dfd524b305f476eebf5fc05c4689ed105df44e66353b0d21212a2192c9c26c"
        tlp = "clear"

    strings:
        // Solana C2 resolution
        $sol_rpc1 = "getSignaturesForAddress" ascii wide
        $sol_rpc2 = "getTransaction" ascii wide
        $sol_memo = "jsonParsed" ascii wide

        // Anti-analysis sandbox DLL checks
        $sandbox1 = "sbiedll.dll" ascii wide nocase
        $sandbox2 = "api_log.dll" ascii wide nocase
        $sandbox3 = "vmcheck.dll" ascii wide nocase
        $sandbox4 = "wpespy.dll" ascii wide nocase
        $sandbox5 = "cmdvrt64.dll" ascii wide nocase
        $sandbox6 = "avghookx.dll" ascii wide nocase
        $sandbox7 = "snxhk.dll" ascii wide nocase
        $sandbox8 = "guard32.dll" ascii wide nocase

        // BSoD self-protection
        $bsod1 = "NtSetInformationProcess" ascii wide
        $bsod2 = "SeDebugPrivilege" ascii wide
        $bsod3 = "ProcessBreakOnTermination" ascii wide

        // VM MAC OUI detection
        $mac_vmware1 = "00:05:69" ascii wide
        $mac_vmware2 = "00:0c:29" ascii wide
        $mac_vmware3 = "00:50:56" ascii wide
        $mac_vbox    = "08:00:27" ascii wide
        $mac_hyperv  = "00:15:5d" ascii wide
        $mac_xen     = "00:16:3e" ascii wide
        $mac_parallels = "00:1c:42" ascii wide

        // Overlord RAT capability strings (Go binary)
        $cap_keylog = "GetAsyncKeyState" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 50MB and (
            // Tier 1: Solana C2 resolution (campaign-specific)
            (2 of ($sol_rpc1, $sol_rpc2, $sol_memo) and 3 of ($sandbox*)) or
            // Tier 2: BSoD + sandbox evasion combo
            (2 of ($bsod*) and 4 of ($sandbox*)) or
            // Tier 3: VM MAC + sandbox + capability combo
            (3 of ($mac_*) and 3 of ($sandbox*) and $cap_keylog)
        )
}

rule UAT12643_GoodGame_Stealer
{
    meta:
        description = "Detects the Good Game infostealer (PyInstaller-packed) used by UAT-12643. Keys on the stealer's distinctive file naming conventions (SK_ archive prefix, url_opened_ flag files), targeted application strings (browser credential paths, Discord token patterns, crypto wallet names), and exfiltration patterns."
        author = "Actioner"
        date = "2026-11-28"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash1 = "16622bb8df60403217ccf8e326e2e9e718e01c85d7b52fe5c5e1cf44d62d25c8"
        hash2 = "5a52d6773840fd5ab45d781d572d9fbd6a8dacb08dcda65036ce8b28548a5224"
        hash3 = "b0b636f5c7e40af94aacf9ebd9a696dac57debcd628127414248908562380d33"
        tlp = "clear"

    strings:
        // Stealer archive naming
        $archive_prefix = "SK_" ascii wide

        // Exfiltration paths within archive
        $path1 = "system_infos.txt" ascii wide
        $path2 = "Passwords" ascii wide
        $path3 = "Session Files/Wallets/" ascii wide
        $path4 = "Session Files/Game Launchers/" ascii wide
        $path5 = "Session Files/Apps/Telegram/" ascii wide
        $path6 = "Interesting Files/" ascii wide
        $path7 = "Screenshot/" ascii wide
        $path8 = "Webcam/" ascii wide

        // Discord token theft
        $discord_prefix = "dQw4w9WgXcQ:" ascii wide

        // Exfil targets
        $gofile = "upload.gofile.io" ascii wide nocase
        $gofile_path = "/uploadFile" ascii wide

        // Python stealer module names
        $pymod1 = "final_build" ascii wide
        $pymod2 = "kora" ascii wide

        // Persistence value
        $persist = "Zoipers" ascii wide

        // DisableTaskMgr tampering
        $taskmgr = "DisableTaskMgr" ascii wide

    condition:
        filesize < 100MB and (
            // Tier 1: Archive structure indicators
            (3 of ($path*) and $archive_prefix) or
            // Tier 2: Discord + exfil + persistence
            ($discord_prefix and ($gofile or $gofile_path) and $persist) or
            // Tier 3: Python modules + exfil + taskmgr
            (all of ($pymod*) and $taskmgr and ($gofile or $gofile_path)) or
            // Tier 4: Broad stealer behavior
            (5 of ($path*) and ($gofile or $gofile_path))
        )
}

rule UAT12643_Clipboard_Hijacker
{
    meta:
        description = "Detects the UAT-12643 clipboard hijacker, a Windows x64 C++ binary that polls the clipboard every 500ms and replaces cryptocurrency addresses with attacker-controlled ones. Keys on the mutex name, persistence artifacts, XOR-encrypted wallet data section, and VM detection strings."
        author = "Actioner"
        date = "2026-11-28"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash1 = "f1e5174084bfded283b9dcf081615478e6941d12b652793197556beb72cc7588"
        tlp = "clear"

    strings:
        // Distinctive mutex
        $mutex = "UuuRjinBZPBMIjnc" ascii wide

        // Persistence artifact
        $persist_name = "MsgEdgeUpdate" ascii wide

        // VM detection strings (clipboard hijacker specific)
        $vm1 = "VBOX" ascii wide
        $vm2 = "VMWARE" ascii wide
        $vm3 = "QEMU" ascii wide
        $vm4 = "SANDBOX" ascii wide

        // Clipboard API usage
        $clip1 = "OpenClipboard" ascii wide
        $clip2 = "GetClipboardData" ascii wide
        $clip3 = "SetClipboardData" ascii wide
        $clip4 = "EmptyClipboard" ascii wide

        // File attribute manipulation (Hidden + System)
        $attrib = "SetFileAttributesW" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 20MB and (
            // Tier 1: Exact mutex match (campaign-specific)
            $mutex or
            // Tier 2: Persistence + clipboard manipulation combo
            ($persist_name and 3 of ($clip*)) or
            // Tier 3: VM detection + clipboard + hiding combo
            (3 of ($vm*) and 3 of ($clip*) and $attrib)
        )
}

rule UAT12643_HTA_Stager
{
    meta:
        description = "Detects the HTA stager used by UAT-12643 for initial access. The stager uses MSXML2.ServerXMLHTTP for download and ADODB.Stream to write the payload to %TEMP%\\s.exe."
        author = "Actioner"
        date = "2026-11-28"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash1 = "c8f9ce4b58acec3ce5640041cbc6d4802e30b2dded4a88766ee2de2cefde45f7"
        tlp = "clear"

    strings:
        $xmlhttp = "MSXML2.ServerXMLHTTP" ascii wide nocase
        $adodb = "ADODB.Stream" ascii wide nocase
        $temp_exe = "\\s.exe" ascii wide
        $staging_ip = "41.216.188.11" ascii wide
        $hta_tag = "<HTA:APPLICATION" ascii wide nocase

    condition:
        filesize < 1MB and (
            ($xmlhttp and $adodb and $temp_exe) or
            ($hta_tag and $staging_ip) or
            ($xmlhttp and $adodb and $staging_ip)
        )
}

rule UAT12643_MSBuild_Stager
{
    meta:
        description = "Detects the MSBuild inline C# stager (dl.xml) used by UAT-12643. The XML project file uses CodeTaskFactory for in-memory execution and spoofs a Microsoft BITS User-Agent string."
        author = "Actioner"
        date = "2026-11-28"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash1 = "19ca4e0e8e7dd62d130afbfed49646f1566dce2633cf937b848d990da3e3e9a2"
        tlp = "clear"

    strings:
        $codetask = "CodeTaskFactory" ascii wide nocase
        $bits_ua = "Microsoft BITS/7.8" ascii wide
        $staging_ip = "41.216.188.11" ascii wide
        $msbuild_ns = "http://schemas.microsoft.com/developer/msbuild" ascii wide nocase
        $using_csharp = "UsingTask" ascii wide

    condition:
        filesize < 1MB and (
            ($codetask and $bits_ua) or
            ($codetask and $staging_ip) or
            ($msbuild_ns and $bits_ua and $using_csharp)
        )
}

rule UAT12643_LNK_Stager
{
    meta:
        description = "Detects malicious LNK files used by UAT-12643 for initial access. The LNK files abuse MpCmdRun.exe -DownloadFile or certutil -urlcache to download payloads, and were built on machine win-8oa3ccqae4d."
        author = "Actioner"
        date = "2026-11-28"
        reference = "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
        hash1 = "1b268a08e83839f6e89acf0987657776398de2ba5a323b04b1dd3925ce3a5b45"
        hash2 = "eb5730784e7d63e1fe38a0bc28be8f2210666662e9a660efcc3282f0489ef870"
        hash3 = "68786345f67152eb0d52bb198b5904924cfbdbf50c078432e5329e5d02fc6659"
        tlp = "clear"

    strings:
        // Build machine name
        $buildhost = "win-8oa3ccqae4d" ascii wide nocase

        // LOLBIN abuse patterns
        $mpcmd = "MpCmdRun" ascii wide
        $mpcmd_dl = "-DownloadFile" ascii wide
        $certutil = "certutil" ascii wide
        $certutil_url = "-urlcache" ascii wide

        // Staging IP
        $staging_ip = "41.216.188.11" ascii wide

        // LNK magic bytes
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }

    condition:
        $lnk_magic at 0 and filesize < 10MB and (
            $buildhost or
            ($mpcmd and $mpcmd_dl and $staging_ip) or
            ($certutil and $certutil_url and $staging_ip)
        )
}
