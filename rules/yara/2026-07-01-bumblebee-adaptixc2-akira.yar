// YARA rules for BumbleBee / AdaptixC2 / Akira ransomware incident
// Source: https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
// Generated: 2026-07-01 v2 (REVISED)

rule Bumblebee_Trojanized_MSI_Installer
{
    meta:
        description = "Detects BumbleBee trojanized MSI installers based on embedded DLL sideloading components (consent.exe + msimg32.dll pattern)"
        author = "Actioner"
        date = "2026-07-01"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash = "186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da"
        confidence = "high"

    strings:
        $msi_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $s1 = "consent.exe" ascii wide
        $s2 = "msimg32.dll" ascii wide
        $s3 = "ApplicationInstallationFolder" ascii wide
        $s4 = "ManageEngine" ascii wide nocase

    condition:
        $msi_magic at 0 and $s3 and ($s1 or $s2) and $s4
}

rule Bumblebee_Loader_msimg32_DLL
{
    meta:
        description = "Detects BumbleBee first-stage loader DLL masquerading as msimg32.dll with dictionary-derived gibberish metadata"
        author = "Actioner"
        date = "2026-07-01"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash_md5 = "ca8646dfc88423bb9fffda811160cebe"
        hash_sha256 = "a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331"
        target = "memory dump / unpacked sample"
        confidence = "high"

    strings:
        $pe_magic = "MZ"
        $dll_name = "msimg32.dll" ascii wide
        $api1 = "GetSystemDefaultLocaleName" ascii
        $api2 = "ExitProcess" ascii
        $pesieve = "hasherezade_pussy" ascii wide
        $export1 = "vSetDdrawflag" ascii
        $export2 = "GradientFill" ascii
        $geofence = "be-BY" ascii wide

    condition:
        $pe_magic at 0 and $dll_name and (
            $pesieve or
            ($api1 and $api2 and $geofence and ($export1 or $export2))
        )
}

rule Akira_Ransomware_Locker
{
    meta:
        description = "Detects Akira ransomware locker binary based on command-line parameter patterns and behavioral strings"
        author = "Actioner"
        date = "2026-07-01"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash_sha256 = "de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d"
        confidence = "medium"

    strings:
        $pe_magic = "MZ"
        $s1 = "akira_readme.txt" ascii wide nocase
        $s2 = ".akira" ascii wide
        $cmd1 = "-p=" ascii
        $cmd2 = "-n=" ascii
        $ransom1 = "your data are stolen" ascii wide nocase
        $ransom2 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4cez" ascii wide nocase

    condition:
        $pe_magic at 0 and (
            ($s1 and $s2) or
            ($s1 and ($cmd1 or $cmd2)) or
            ($ransom1 or $ransom2)
        )
}
