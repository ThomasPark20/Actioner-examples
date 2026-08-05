/*
 * CaptiveCrunch / Midnight Blizzard Hotel Wi-Fi Campaign - YARA Rules
 * Generated: 2026-08-05
 * Reference: https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
 * 3 rules
 */

rule APT29_CornFlake_RAT : CaptiveCrunch MidnightBlizzard
{
    meta:
        description = "Detects CornFlake RAT (Go-based) deployed by Midnight Blizzard in the CaptiveCrunch hotel Wi-Fi campaign. Keys on distinctive strings including service name, config file, evasion window themes, and C2 patterns."
        author = "Actioner"
        date = "2026-08-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        hash = "918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // Service and persistence artifacts
        $svc1 = "svchost32" ascii wide
        $svc2 = "Cloud Sync Service" ascii wide
        $cfg  = "sync.dat" ascii wide

        // Fake progress window themes
        $theme1 = "winupdate" ascii
        $theme2 = "defender" ascii
        $theme3 = "directx" ascii
        $theme4 = "vcredist" ascii
        $theme5 = "sysopt" ascii
        $theme6 = "netfix" ascii

        // Go binary indicators
        $go1 = "runtime.goexit" ascii
        $go2 = "main.main" ascii

        // Crypto indicators (ECDH P-256)
        $crypto1 = "P-256" ascii
        $crypto2 = "ecdh" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 25MB and
        (
            ($svc1 and $svc2) or
            ($svc1 and $cfg and 2 of ($theme*)) or
            ($svc1 and 1 of ($go*) and 1 of ($crypto*))
        )
}

rule APT29_CornFlake_RAT_GoStrings : CaptiveCrunch MidnightBlizzard
{
    meta:
        description = "Detects CornFlake RAT via Go compilation artifacts combined with distinctive operational strings. Broader variant targeting the Go binary structure."
        author = "Actioner"
        date = "2026-08-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        hash = "918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593"
        tlp = "WHITE"
        severity = "high"

    strings:
        $go_build = "Go build" ascii
        $go_runtime = "runtime.goexit" ascii

        // Capability strings
        $cap1 = "keylog" ascii nocase
        $cap2 = "clipboard" ascii nocase
        $cap3 = "screenshot" ascii nocase
        $cap4 = "remote_shell" ascii nocase
        $cap5 = "file_exfil" ascii nocase
        $cap6 = "usb_monitor" ascii nocase

        $svc = "svchost32" ascii wide
        $cfg = "sync.dat" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 25MB and
        1 of ($go*) and
        $svc and
        $cfg and
        2 of ($cap*)
}

rule APT29_ChocoShell_Infostealer : CaptiveCrunch MidnightBlizzard
{
    meta:
        description = "Detects ChocoShell PowerShell infostealer used by Midnight Blizzard in the CaptiveCrunch campaign. Targets browser credentials, M365 tokens, and Wi-Fi creds with multiple UAC bypass techniques."
        author = "Actioner"
        date = "2026-08-05"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        hash = "be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // AMSI bypass via .NET reflection
        $amsi1 = "amsiInitFailed" ascii wide nocase
        $amsi2 = "AmsiUtils" ascii wide nocase

        // UAC bypass registry paths
        $uac1 = "Environment\\windir" ascii wide nocase
        $uac2 = "wsreset" ascii wide nocase
        $uac3 = "Folder\\shell\\open\\command" ascii wide nocase
        $uac4 = "sdclt" ascii wide nocase
        $uac5 = "SilentCleanup" ascii wide nocase

        // C2 beacon endpoints
        $c2_1 = "pixel.gif" ascii wide
        $c2_2 = "polyfill-7e2b.min.js" ascii wide
        $c2_3 = "/t/event" ascii wide

        // Browser credential theft targets
        $browser1 = "App-Bound Encryption" ascii wide nocase
        $browser2 = "NSS" ascii wide
        $browser3 = "tbres_" ascii wide

        // Wi-Fi credential harvesting
        $wifi = "netsh wlan show profile" ascii wide nocase

        // PowerShell indicators
        $ps1 = "-NoP" ascii wide nocase
        $ps2 = "Invoke-Expression" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            (2 of ($amsi*) and 1 of ($uac*)) or
            (1 of ($amsi*) and 2 of ($uac*) and 1 of ($c2_*)) or
            (2 of ($c2_*) and 1 of ($browser*) and 1 of ($uac*)) or
            ($wifi and 1 of ($amsi*) and 1 of ($c2_*)) or
            (1 of ($ps*) and 1 of ($amsi*) and 2 of ($uac*) and 1 of ($browser*))
        )
}
