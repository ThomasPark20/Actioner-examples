import "pe"

rule APT_Cavern_Manticore_Agent : cavern iran
{
    meta:
        description = "Detects Cavern Manticore backdoor agent (uxtheme.dll) via mutex names, developer artifacts, and module-loading strings"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/"
        hash = "37e123bd7998af4eae32718ce254776f36365a80ba56952593dab46f536d4066"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $mutex1 = "MYMUTEX123HELLP" ascii wide
        $mutex2 = "MYMUTEX123HELLP02" ascii wide
        $mutex3 = "MYMUTEX123HELLP04" ascii wide
        $pdb = "\\Users\\rick\\Desktop\\Modules\\cavern\\" ascii
        $err1 = "where is get_version" ascii wide
        $err2 = "DLL not found...Maybe you didn't upload it" ascii wide
        $mod1 = "n-HTCommp.dll" ascii wide
        $mod2 = "config.txt" ascii wide
        $delim1 = "_;;_" ascii wide
        $delim2 = "_,_" ascii wide
        $export = "EnableThemeDialogTexture" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($mutex*) or
            $pdb or
            (1 of ($err*)) or
            (3 of ($mod*, $delim*, $export))
        )
}

rule APT_Cavern_Manticore_CommModule : cavern iran
{
    meta:
        description = "Detects Cavern Manticore communication module (n-HTCommp.dll) via C2 endpoint patterns and transport verb strings"
        author = "Actioner"
        date = "2026-07-10"
        reference = "https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/"
        hash = "a4aa217def4c38f4ecacdf47b1cd687f60cc74c18ab75195be3c4357a790bf41"
        tlp = "WHITE"
        severity = "high"

    strings:
        $uri1 = "/profile" ascii wide
        $uri2 = "/gallery" ascii wide
        $uri3 = "/socket" ascii wide
        $hdr = "X-User-token" ascii wide
        $ua = "Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0" ascii wide
        $typo1 = "tunnel message receivecd" ascii wide
        $typo2 = "handeling connect ms" ascii wide
        $cfg1 = "Cvn.cfg.A" ascii wide
        $cfg2 = "Cvn.cfg.U" ascii wide
        $ns = "CAV3RN" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($hdr and 1 of ($uri*)) or
            ($ua and 1 of ($uri*, $hdr)) or
            any of ($typo*) or
            (1 of ($cfg*) and 1 of ($uri*)) or
            $ns
        )
}
