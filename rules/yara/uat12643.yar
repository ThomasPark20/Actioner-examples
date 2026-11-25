rule Malware_OverlordRAT_Core_Strings
{
    meta:
        description = "Detects Overlord RAT via distinctive string artifacts including BSoD trigger, Solana blockchain C2 resolution, and sandbox evasion checks"
        author = "Actioner"
        date = "2026-11-25"
        reference = "https://blog.talosintelligence.com/uat-12643-overlord-rat/"
        severity = "critical"

    strings:
        $bsod1 = "NtRaiseHardError" ascii fullword
        $bsod2 = "NtSetInformationProcess" ascii fullword

        $sol1 = "getSignaturesForAddress" ascii
        $sol2 = "getTransaction" ascii
        $sol3 = "jsonParsed" ascii
        $sol4 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr" ascii

        $cam1 = "avicap32.dll" ascii nocase
        $cam2 = "capCreateCaptureWindow" ascii fullword

        $key1 = "GetAsyncKeyState" ascii fullword
        $key2 = "GetForegroundWindow" ascii fullword

        $sb1 = "sbiedll.dll" ascii nocase
        $sb2 = "api_log.dll" ascii nocase
        $sb3 = "vmcheck.dll" ascii nocase
        $sb4 = "wpespy.dll" ascii nocase
        $sb5 = "cmdvrt64.dll" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($sol*) and 1 of ($bsod*)) or
            (2 of ($sol*) and 1 of ($cam*)) or
            (2 of ($sol*) and 1 of ($key*)) or
            (1 of ($bsod*) and 3 of ($sb*) and (1 of ($cam*) or 1 of ($key*)))
        )
}

rule Malware_UAT12643_ClipboardHijacker
{
    meta:
        description = "Detects UAT-12643 clipboard hijacker (MsgEdgeUpdate) via unique mutex and crypto address replacement functionality"
        author = "Actioner"
        date = "2026-11-25"
        reference = "https://blog.talosintelligence.com/uat-12643-overlord-rat/"
        severity = "high"

    strings:
        $mutex = "UuuRjinBZPBMIjnc" ascii wide
        $name1 = "MsgEdgeUpdate" ascii wide
        $clip1 = "GetClipboardData" ascii fullword
        $clip2 = "SetClipboardData" ascii fullword

        $btc = "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$" ascii
        $eth = "^0x[0-9a-fA-F]{40}$" ascii
        $sol = "^[1-9A-HJ-NP-Za-km-z]{32,44}$" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            $mutex or
            ($name1 and $clip1 and $clip2 and 1 of ($btc, $eth, $sol))
        )
}

rule Malware_UAT12643_GoodGameStealer
{
    meta:
        description = "Detects UAT-12643 Good Game Stealer via gofile.io exfiltration endpoint, Discord webhook reporting, and browser credential theft indicators"
        author = "Actioner"
        date = "2026-11-25"
        reference = "https://blog.talosintelligence.com/uat-12643-overlord-rat/"
        severity = "high"

    strings:
        $exfil1 = "gofile.io" ascii wide
        $exfil2 = "store.gofile.io" ascii wide
        $discord = "discord.com/api/webhooks" ascii wide

        $brw1 = "Login Data" ascii wide
        $brw2 = "Web Data" ascii wide
        $brw3 = "Cookies" ascii wide
        $brw4 = "Local State" ascii wide

        $path1 = "\\AppData\\Local\\Google\\Chrome\\User Data" ascii
        $path2 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles" ascii

        $name1 = "Zoipers" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($name1 and 1 of ($exfil*)) or
            (1 of ($exfil*) and $discord and 2 of ($brw*)) or
            ($discord and 3 of ($brw*) and 1 of ($path*))
        )
}
