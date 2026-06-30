rule bumblebee_loader_msimg32_dll
{
    meta:
        description = "Bumblebee first-stage loader DLL (msimg32.dll) used for DLL sideloading via consent.exe in SEO poisoning campaign delivering AdaptixC2 and Akira ransomware (DFIR Report case TB36726)"
        author = "Actioner"
        date = "2026-06-30"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash = "a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331"
    strings:
        $mz = "MZ" at 0
        $dga1 = "ev2sirbd269o5j.org" ascii wide
        $dga2 = "2rxyt8yrhq0bgj.org" ascii wide
        $dga3 = "d1hmxkpwby0d4s.org" ascii wide
        $dga4 = "yj6jurm5qqkye5.org" ascii wide
        $dga5 = "ewujsfb1dp5ran.org" ascii wide
        $dga6 = "8doj8uvx604eck.org" ascii wide
        $dga7 = "kwywztxoo2xdot.org" ascii wide
        $export = "msimg32" ascii
        $sideload = "consent.exe" ascii wide
    condition:
        $mz and (2 of ($dga*) or ($export and $sideload))
}

rule bumblebee_msi_installer
{
    meta:
        description = "Trojanized ManageEngine OpManager MSI installer delivering Bumblebee loader via SEO poisoning (DFIR Report case TB36726)"
        author = "Actioner"
        date = "2026-06-30"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash = "186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da"
    strings:
        $msi_magic = {D0 CF 11 E0 A1 B1 1A E1}
        $product1 = "ManageEngine" ascii wide nocase
        $product2 = "OpManager" ascii wide nocase
        $signer = "LLC Resource+" ascii wide
        $payload_dll = "msimg32.dll" ascii wide
        $payload_exe = "consent.exe" ascii wide
        $folder = "ApplicationInstallationFolder" ascii wide
    condition:
        $msi_magic at 0 and ($signer or ($product1 and $product2 and ($payload_dll or $payload_exe or $folder)))
}

rule adaptixc2_memory_artifact
{
    meta:
        description = "AdaptixC2 framework memory artifacts including characteristic DLL name found in injected process memory (DFIR Report case TB36726)"
        author = "Actioner"
        date = "2026-06-30"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash = "a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331"
    strings:
        $artifact1 = "hasherezade_pussy.dll" ascii wide
        $artifact2 = "ActiveC2" ascii wide
        $artifact3 = "AdaptixC2" ascii wide
        $artifact4 = "Adaptix" ascii wide
        $wab_rename = "AdgNsy.exe" ascii wide
    condition:
        any of ($artifact1, $artifact2, $artifact3) or ($artifact4 and $wab_rename)
}

rule akira_ransomware_locker
{
    meta:
        description = "Akira ransomware binary (locker.exe / win.exe) with characteristic command-line argument patterns (DFIR Report case TB36726)"
        author = "Actioner"
        date = "2026-06-30"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        hash = "de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d"
    strings:
        $mz = "MZ" at 0
        $arg_path = "-p=" ascii
        $arg_threads = "-n=" ascii
        $arg_netonly = "netonly" ascii
        $ransom1 = "akira" ascii wide nocase
        $ransom2 = ".akira" ascii wide
        $shadow = "Win32_Shadowcopy" ascii wide
        $onion = ".onion" ascii
    condition:
        $mz and (($arg_path and $arg_threads) or ($ransom1 and ($shadow or $onion)) or ($ransom2 and $mz))
}
