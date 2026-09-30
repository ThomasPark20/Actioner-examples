rule APT_StarBlizzard_CosmicPulse_Dropper
{
    meta:
        description = "Detects Star Blizzard CosmicPulse downloader CPL files and associated archive lures based on known file hashes and characteristic strings"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/"
        tlp = "WHITE"
        severity = "critical"
        hash1 = "9707a8694e954e9ee13e839d6e5905ce626c0837c7c90da6d1025bfbe152866b"
        hash2 = "1f2096ff906915fbf80778f0636446206197351f7e271af97936eeb6f32c179d"
        hash3 = "699e92a9e0edf7835879d5697bc67138c0b137117f459caf1a44df357407cad9"
        hash4 = "24b6e36a09eb2acfc2a95478ca685acb7593b1689be6a4a639fe0d222393cfa7"
        hash5 = "dd98dbc1a55afe6fd0ed2ed53a79c76f6bde15081a0060422185b74eb1799ee4"

    strings:
        $mollis = "Software\\Classes\\.mollis" ascii wide
        $schtask1 = "Internet Quality Test Connection" ascii wide
        $schtask2 = "Network Configuration Manager" ascii wide
        $schtask3 = "System Health Monitor" ascii wide
        $ctrl_rundll = "Control_RunDLL" ascii wide
        $cpl_export = "CPlApplet" ascii

    condition:
        (uint16(0) == 0x5A4D and filesize < 10MB and
            (
                $mollis or
                ($cpl_export and 2 of ($schtask*)) or
                ($ctrl_rundll and any of ($schtask*))
            )
        )
        or
        (filesize < 50MB and 3 of ($schtask1, $schtask2, $schtask3, $mollis))
}

rule APT_StarBlizzard_RedFlick_PDF_Steganography
{
    meta:
        description = "Detects PDF files containing embedded payloads using the cAB magic header technique employed by Star Blizzard RedFlick campaigns"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $pdf_header = "%PDF" ascii
        $magic_cab = "cAB" ascii
        $b64_block = /cAB[A-Za-z0-9+\/]{200,}/

    condition:
        $pdf_header at 0 and
        filesize < 20MB and
        ($magic_cab and $b64_block)
}
