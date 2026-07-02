rule BumbleBee_Loader_msimg32
{
    meta:
        description = "Detects BumbleBee loader delivered as msimg32.dll via DLL side-loading with consent.exe in trojanized MSI installers"
        author = "Actioner"
        date = "2026-07-02"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash = "a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $dll_name = "msimg32.dll" ascii wide
        $side_load = "consent.exe" ascii wide
        $folder = "ApplicationInstallationFolder" ascii wide
        $wab = "AdgNsy.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (1 of ($folder, $wab)) and (1 of ($dll_name, $side_load))
}

rule Akira_Ransomware_Locker
{
    meta:
        description = "Detects Akira ransomware locker executable based on command-line patterns and Akira-specific strings. Speculative: built from documented behavioral artifacts without access to the actual sample binary."
        author = "Actioner"
        date = "2026-07-02"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash = "de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d"
        tlp = "WHITE"
        severity = "high"

    strings:
        $param_p = "-p=" ascii
        $param_n = "-n=" ascii
        $akira1 = "akira" ascii nocase
        $ext = ".akira" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (1 of ($akira*, $ext)) and ($param_p and $param_n)
}
