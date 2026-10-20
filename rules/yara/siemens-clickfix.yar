rule CVE_2026_110936_AllMyBasic_MSI {
    meta:
        description = "Detects AllMyBasic.msi used in CVE-2026-110936 Siemens Software Center DLL sideloading attacks"
        author = "Actioner CTI"
        date = "2026-10-20"
        reference = "https://productcert.siemens.com/news/2026/10/19/active-exploitation-of-cve-2026-110936-in-siemens-software-center/"
        hash = "f4d7c5321bb0d1bda439304a753bcf9b467b98ca53c7e9493b9c2c3451092e4a"
        severity = "high"

    strings:
        $msi_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $s1 = "AllMyBasic" ascii wide
        $s2 = "SM Software Provisioning Service" ascii wide
        $s3 = "SiemensSoftwareCenter" ascii wide
        $s4 = "archive.dll" ascii wide

    condition:
        $msi_magic at 0 and ($s1 or ($s2 and $s3) or ($s3 and $s4))
}

rule CVE_2026_110936_Archive_DLL {
    meta:
        description = "Detects the malicious archive.dll sideloaded by Siemens Software Center in CVE-2026-110936. Note: strings are inferred from observed filesystem artifacts, not verified against the sample binary."
        author = "Actioner CTI"
        date = "2026-10-20"
        reference = "https://productcert.siemens.com/news/2026/10/19/active-exploitation-of-cve-2026-110936-in-siemens-software-center/"
        hash = "3fdcc7d7d049a89711fb31fb236940a1c5a09d899143ffd20c3c41fb1f2cf491"
        severity = "medium"

    strings:
        $mz = { 4D 5A }
        $s1 = "activate.bak" ascii wide
        $s2 = "statinfosta.DB" ascii wide
        $s3 = "ftc.uml" ascii wide
        $s4 = "FTSuite" ascii wide

    condition:
        $mz at 0 and 2 of ($s1, $s2, $s3, $s4)
}

rule Romulus_ClickFix_Staging_Script {
    meta:
        description = "Detects PowerShell staging scripts used by the Romulus ClickFix delivery platform"
        author = "Actioner CTI"
        date = "2026-10-20"
        reference = "https://www.forescout.com/blog/romulus-analysis-of-a-new-multi-payload-clickfix-delivery-platform/"
        severity = "medium"

    strings:
        $ps1 = "$env:__ST" ascii nocase
        $ps2 = "[scriptblock]::Create" ascii nocase
        $ps3 = "$MyInvocation.MyCommand.Path" ascii nocase
        $ps4 = "Unblock-File" ascii nocase
        $ps5 = "/qn /norestart" ascii nocase

    condition:
        ($ps1 and $ps2) or ($ps1 and 2 of ($ps3, $ps4, $ps5))
}
